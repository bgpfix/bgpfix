package bmp

import (
	"context"
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/bgpfix/bgpfix/afi"
	"github.com/bgpfix/bgpfix/caps"
	"github.com/bgpfix/bgpfix/meta"
	"github.com/bgpfix/bgpfix/msg"
	"github.com/bgpfix/bgpfix/pipe"
	"github.com/stretchr/testify/require"
)

// an UPDATE for 10.0.0.0/24 with ADD-PATH Path Identifier 7
var addpathUpdate = append(append([]byte(nil), msg.BgpMarker...),
	0, 45, 2, // length, type
	0, 0, // withdrawn
	0, 14, // attrs: ORIGIN, AS_PATH (empty), NEXT_HOP
	0x40, 1, 1, 0, 0x40, 2, 0, 0x40, 3, 4, 10, 0, 0, 1,
	0, 0, 0, 7, 24, 10, 0, 0) // path id + prefix

// an UPDATE for 2001:db8::/32 in MP_REACH, without a Path Identifier
var mpUpdate = append(append([]byte(nil), msg.BgpMarker...),
	0, 59, 2, // length, type
	0, 0, // withdrawn
	0, 36, // attrs: ORIGIN, AS_PATH (empty), MP_REACH
	0x40, 1, 1, 0, 0x40, 2, 0,
	0x80, 14, 26, 0, 2, 1, 16, 0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0,
	32, 0x20, 1, 0xd, 0xb8)

// testPipe returns a started pipe: Reader needs its message pool
// NB: never stopped, as Pipe.Stop() races with the start events under -race
func testPipe(t *testing.T) *pipe.Pipe {
	p := pipe.NewPipe(context.Background())
	p.Options.Logger = nil
	require.NoError(t, p.Start())
	return p
}

func testOpen(t *testing.T, addpath bool) []byte {
	m := msg.NewMsg().Switch(msg.OPEN)
	m.Open.Caps.Init()
	m.Open.Identifier = netip.MustParseAddr("10.0.0.1")
	m.Open.SetASN(65001)
	if addpath {
		m.Open.Caps.Use(caps.CAP_ADDPATH).(*caps.AddPath).Add(afi.AS_IPV4_UNICAST, caps.ADDPATH_BIDIR)
	}
	require.NoError(t, m.Marshal(caps.Caps{}))
	return append(binary.BigEndian.AppendUint16(append([]byte(nil), msg.BgpMarker...), uint16(msg.HEADLEN+len(m.Data))), append([]byte{byte(msg.OPEN)}, m.Data...)...)
}

// Reader must take ADD-PATH from the OPENs in Peer Up, and forget it on Peer Down
func TestReader_AddPath(t *testing.T) {
	for _, addpath := range []bool{true, false} {
		br := NewReader(testPipe(t), nil)

		peer := Peer{Address: netip.MustParseAddr("10.0.0.1"), AS: 65001}
		var stream []byte
		add := func(set func(b *Bmp)) {
			b := NewBmp()
			b.Peer = peer
			set(b)
			require.NoError(t, b.Marshal())
			stream = append(stream, b.Bytes()...)
		}
		open := testOpen(t, addpath)
		add(func(b *Bmp) { b.SetInitiation("rtr1", "test") })
		add(func(b *Bmp) { b.SetPeerUp(&PeerUp{SentOpen: open, RcvdOpen: open}) })
		add(func(b *Bmp) { b.Type = MSG_ROUTE_MONITORING; b.BgpData = addpathUpdate })
		add(func(b *Bmp) { b.Type = MSG_ROUTE_MONITORING; b.BgpData = mpUpdate }) // NB: no ADD-PATH on IPv6
		add(func(b *Bmp) { b.SetPeerDown(nil) })
		add(func(b *Bmp) { b.Type = MSG_ROUTE_MONITORING; b.BgpData = addpathUpdate })

		// NB: the callback drops the messages, so look at them right there
		var aps []*meta.AddPath
		var routers, reach []string
		_, err := br.WriteFunc(stream, func(m *msg.Msg) bool {
			aps = append(aps, m.ParseAddPath)
			routers = append(routers, pipe.GetTags(m)["ROUTER"])
			require.NoError(t, m.Parse(caps.Caps{}))
			for _, p := range m.Update.AllReach() {
				reach = append(reach, p.String())
			}
			return false
		})
		require.NoError(t, err)
		require.EqualValues(t, 1, br.Stats.PeerUp)
		require.EqualValues(t, 1, br.Stats.PeerDown)
		require.Equal(t, []string{"rtr1", "rtr1", "rtr1"}, routers)
		require.Nil(t, aps[2]) // NB: no state after Peer Down
		if addpath {
			require.Equal(t, []afi.AS{afi.AS_IPV4_UNICAST}, aps[0].AS)
			require.Equal(t, []string{"#7#10.0.0.0/24", "2001:db8::/32"}, reach[:2])
		} else {
			require.Equal(t, meta.AddPathOff, aps[0])
		}
	}
}

// Writer output must be a valid BMP session for Reader: ADD-PATH survives the
// synthesized Peer Up, and OnBmp sees the other messages, including statistics
func TestWriter(t *testing.T) {
	var cps caps.Caps
	cps.Use(caps.CAP_AS4)

	// an UPDATE with Path Identifiers, from peer 10.0.0.1
	m := msg.NewMsg()
	_, err := m.FromBytes(addpathUpdate)
	require.NoError(t, err)
	m.ParseAddPath = meta.AddPathOn
	pipe.UseTags(m)["PEER_IP"] = "10.0.0.1"

	b := NewBmp()
	require.NoError(t, b.FromMsg(m, cps))
	require.NoError(t, b.Marshal())
	w := Writer{SysName: "rtr1"}
	stream := append(w.Prepend(nil, b, m, cps), b.Bytes()...)
	stream = append(w.Prepend(stream, b, m, cps), b.Bytes()...) // NB: no second Peer Up

	// a Statistics Report: 5 rejected prefixes, 1000 routes in Adj-RIB-In
	st := NewBmp()
	st.Type, st.Peer = MSG_STATISTICS_REPORT, b.Peer
	st.Data = []byte{0, 0, 0, 2, 0, 0, 0, 4, 0, 0, 0, 5, 0, 7, 0, 8, 0, 0, 0, 0, 0, 0, 3, 0xe8}
	require.NoError(t, st.Marshal())
	stream = append(stream, st.Bytes()...)

	br := NewReader(testPipe(t), nil)
	var types []string
	var stats []uint64
	br.OnBmp = func(bm *Bmp) {
		types = append(types, bm.Type.String())
		bm.Stats(func(typ uint16, as afi.AS, val uint64) { stats = append(stats, uint64(typ), val) })
	}
	var reach []string
	_, err = br.WriteFunc(stream, func(m *msg.Msg) bool {
		require.NoError(t, m.Parse(caps.Caps{}))
		reach = append(reach, m.Update.Reach[0].String())
		return false
	})
	require.NoError(t, err)
	require.Equal(t, []string{"INITIATION", "PEER_UP", "STATISTICS_REPORT"}, types)
	require.Equal(t, []string{"#7#10.0.0.0/24", "#7#10.0.0.0/24"}, reach)
	require.Equal(t, []uint64{0, 5, 7, 1000}, stats)
	require.Equal(t, "rtr1", br.Router)
}
