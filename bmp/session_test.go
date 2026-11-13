package bmp

import (
	"context"
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/bgpfix/bgpfix/afi"
	"github.com/bgpfix/bgpfix/caps"
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
		var flags []int8
		var routers, reach []string
		_, err := br.WriteFunc(stream, func(m *msg.Msg) bool {
			flags = append(flags, m.ParseAddPath)
			if m.AddPath != nil {
				flags[len(flags)-1] = 2 // per family
			}
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
		if addpath {
			require.Equal(t, []int8{2, 2, 0}, flags) // NB: no state after Peer Down
			require.Equal(t, []string{"#7#10.0.0.0/24", "2001:db8::/32"}, reach[:2])
		} else {
			require.Equal(t, []int8{-1, -1, 0}, flags)
		}
	}
}

// in Session mode, Peer Up yields both OPENs and Peer Down its NOTIFICATION
func TestReader_Session(t *testing.T) {
	br := NewReader(testPipe(t), nil)
	br.Session = true

	notify := append(append([]byte(nil), msg.BgpMarker...), 0, 21, 3, 6, 2) // Cease / Administrative Shutdown
	open := testOpen(t, false)
	var stream []byte
	for _, set := range []func(b *Bmp){
		func(b *Bmp) { b.SetPeerUp(&PeerUp{SentOpen: open, RcvdOpen: open}) },
		func(b *Bmp) { b.SetPeerDown(notify) },
	} {
		b := NewBmp()
		b.Peer = Peer{Address: netip.MustParseAddr("10.0.0.1"), AS: 65001}
		set(b)
		require.NoError(t, b.Marshal())
		stream = append(stream, b.Bytes()...)
	}

	var got []string
	_, err := br.WriteFunc(stream, func(m *msg.Msg) bool {
		got = append(got, m.Type.String()+pipe.GetTags(m)["BMP_OPEN"])
		return false
	})
	require.NoError(t, err)
	require.Equal(t, []string{"OPENsent", "OPEN", "NOTIFY"}, got)
}
