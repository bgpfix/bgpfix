// NB: excluded from -race for the same reason as pipe tests: Pipe.Stop()
// has an inherent race handled by recover(), which the detector flags.
//
//go:build !race

package mrt

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/bgpfix/bgpfix/attrs"
	"github.com/bgpfix/bgpfix/meta"
	"github.com/bgpfix/bgpfix/msg"
	"github.com/bgpfix/bgpfix/pipe"
	"github.com/stretchr/testify/require"
)

// attrWK returns a well-known transitive attribute
func attrWK(code byte, body ...byte) []byte {
	return append([]byte{0x40, code, byte(len(body))}, body...)
}

// attrOpt returns an optional non-transitive attribute
func attrOpt(code byte, body ...byte) []byte {
	return append([]byte{0x80, code, byte(len(body))}, body...)
}

// attrsV4 returns a typical v2 IPv4 attr blob: ORIGIN + ASPATH (AS4) + NEXTHOP
func attrsV4(as2 uint32, nh byte) []byte {
	var blob []byte
	blob = append(blob, attrWK(1, 0)...) // ORIGIN IGP
	aspath := []byte{2, 2}               // AS_SEQUENCE, 2 hops
	aspath = appendUint32(aspath, 65000)
	aspath = appendUint32(aspath, as2)
	blob = append(blob, attrWK(2, aspath...)...)
	blob = append(blob, attrWK(3, 192, 0, 2, nh)...) // NEXTHOP
	return blob
}

// attrsV6 returns a v2 IPv6 attr blob: ORIGIN + ASPATH (AS4) + truncated MP_REACH
func attrsV6(nh netip.Addr) []byte {
	var blob []byte
	blob = append(blob, attrWK(1, 0)...) // ORIGIN IGP
	aspath := []byte{2, 1}               // AS_SEQUENCE, 1 hop
	aspath = appendUint32(aspath, 65000)
	blob = append(blob, attrWK(2, aspath...)...)
	mp := append([]byte{16}, nh.AsSlice()...) // nh len + nh only (rfc6396/4.3.4)
	blob = append(blob, attrOpt(14, mp...)...)
	return blob
}

// attrsV6Full is like attrsV6, but with the full rfc4760 MP_REACH form
// as written by RouteViews, including the NLRI for prefix pfx
func attrsV6Full(nh netip.Addr, pfx netip.Prefix) []byte {
	var blob []byte
	blob = append(blob, attrWK(1, 0)...) // ORIGIN IGP
	aspath := []byte{2, 1}               // AS_SEQUENCE, 1 hop
	aspath = appendUint32(aspath, 65000)
	blob = append(blob, attrWK(2, aspath...)...)
	mp := appendUint16(nil, 2)           // AFI IPv6
	mp = append(mp, 1, 16)               // SAFI unicast, nh len
	mp = append(mp, nh.AsSlice()...)     // nh
	mp = append(mp, 0, byte(pfx.Bits())) // reserved, NLRI
	mp = append(mp, pfx.Addr().AsSlice()[:(pfx.Bits()+7)/8]...)
	blob = append(blob, attrOpt(14, mp...)...)
	return blob
}

// makePeerIndex returns a PEER_INDEX_TABLE body with IPv4 AS4 peers
func makePeerIndex(peers ...PeerEntry) []byte {
	buf := []byte{10, 0, 0, 1} // collector id
	buf = appendUint16(buf, 0) // no view name
	buf = appendUint16(buf, uint16(len(peers)))
	for _, pe := range peers {
		buf = append(buf, 0b10) // IPv4 + AS4
		buf = append(buf, pe.BgpId.AsSlice()...)
		buf = append(buf, pe.IP.AsSlice()...)
		buf = appendUint32(buf, pe.AS)
	}
	return buf
}

// makeRibEntry returns one RIB entry
func makeRibEntry(idx uint16, ats []byte) []byte {
	buf := appendUint16(nil, idx)
	buf = appendUint32(buf, 1600000000) // originated
	buf = appendUint16(buf, uint16(len(ats)))
	return append(buf, ats...)
}

// makeRib returns a RIB_IPV*_UNICAST body
func makeRib(seq uint32, pfx netip.Prefix, entries ...[]byte) []byte {
	buf := appendUint32(nil, seq)
	buf = append(buf, byte(pfx.Bits()))
	buf = append(buf, pfx.Addr().AsSlice()[:(pfx.Bits()+7)/8]...)
	buf = appendUint16(buf, uint16(len(entries)))
	for _, e := range entries {
		buf = append(buf, e...)
	}
	return buf
}

// mrtRecord wraps a body in an MRT header
func mrtRecord(typ Type, sub Sub, body []byte) []byte {
	return append(makeMrtHeader(1700000000, typ, sub, uint32(len(body))), body...)
}

var (
	testPeer1 = PeerEntry{netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("192.0.2.2"), 65001}
	testPeer2 = PeerEntry{netip.MustParseAddr("10.0.0.3"), netip.MustParseAddr("192.0.2.3"), 65002}
)

func TestTable_ParsePeerIndex(t *testing.T) {
	raw := mrtRecord(TABLE_DUMP2, PEER_INDEX_TABLE, makePeerIndex(testPeer1, testPeer2))

	m := NewMrt()
	_, err := m.FromBytes(raw)
	require.NoError(t, err)
	require.NoError(t, m.Parse())
	require.Equal(t, TABLE_DUMP2, m.Upper)

	tab := &m.Table
	require.Equal(t, netip.MustParseAddr("10.0.0.1"), tab.CollectorId)
	require.Equal(t, []PeerEntry{testPeer1, testPeer2}, tab.Peers)
}

func TestTable_ParseRibV4(t *testing.T) {
	pfx := netip.MustParsePrefix("10.128.0.0/9")
	body := makeRib(7, pfx,
		makeRibEntry(0, attrsV4(65001, 1)),
		makeRibEntry(1, attrsV4(65002, 2)))
	raw := mrtRecord(TABLE_DUMP2, RIB_IPV4_UNICAST, body)

	m := NewMrt()
	_, err := m.FromBytes(raw)
	require.NoError(t, err)
	require.NoError(t, m.Parse())

	tab := &m.Table
	require.Equal(t, uint32(7), tab.Seq)
	require.Equal(t, pfx, tab.Prefix.Prefix)
	require.Len(t, tab.Entries, 2)
	require.Equal(t, uint16(0), tab.Entries[0].PeerIndex)
	require.Equal(t, uint16(1), tab.Entries[1].PeerIndex)
	require.Equal(t, time.Unix(1600000000, 0).UTC(), tab.Entries[0].Originated)
	require.Equal(t, attrsV4(65001, 1), tab.Entries[0].Attrs)
}

func TestTable_ParseV1(t *testing.T) {
	// view + seq + prefix + plen + status + originated + peer ip + peer as + attrs
	ats := attrWK(1, 0)                               // ORIGIN IGP
	ats = append(ats, attrWK(2, 2, 1, 0xfd, 0xe8)...) // ASPATH, 2-byte AS 65000
	ats = append(ats, attrWK(3, 192, 0, 2, 1)...)     // NEXTHOP

	body := appendUint16(nil, 0)          // view
	body = appendUint16(body, 42)         // seq
	body = append(body, 10, 128, 0, 0)    // prefix
	body = append(body, 9, 1)             // plen, status
	body = appendUint32(body, 1600000000) // originated
	body = append(body, 192, 0, 2, 2)     // peer IP
	body = appendUint16(body, 65001)      // peer AS
	body = appendUint16(body, uint16(len(ats)))
	body = append(body, ats...)
	raw := mrtRecord(TABLE_DUMP, TD_IPV4, body)

	m := NewMrt()
	_, err := m.FromBytes(raw)
	require.NoError(t, err)
	require.NoError(t, m.Parse())

	tab := &m.Table
	require.Equal(t, uint32(42), tab.Seq)
	require.Equal(t, netip.MustParsePrefix("10.128.0.0/9"), tab.Prefix.Prefix)
	require.Len(t, tab.Peers, 1)
	require.Equal(t, uint32(65001), tab.Peers[0].AS)
	require.Len(t, tab.Entries, 1)
	require.Equal(t, ats, tab.Entries[0].Attrs)
}

// tableReaderTest feeds raw MRT records through a Reader and collects the output
func tableReaderTest(t *testing.T, raw []byte) ([]*msg.Msg, *Reader) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	p := pipe.NewPipe(ctx)
	p.Options.Logger = nil
	p.Options.Caps = false
	in := p.Options.AddInput(meta.DIR_R)
	br := NewReader(p, in)

	require.NoError(t, p.Start())

	// collect messages from the R output
	var msgs []*msg.Msg
	done := make(chan struct{})
	go func() {
		defer close(done)
		for m := range p.R.Out {
			msgs = append(msgs, m)
		}
	}()

	_, err := br.Write(raw)
	require.NoError(t, err)
	require.NoError(t, br.Flush(nil))

	p.Stop()
	<-done
	return msgs, br
}

func TestTableReader_V2_Aggregation(t *testing.T) {
	shared := attrsV4(65001, 1) // same attrs for 3 prefixes
	other := attrsV4(65099, 9)

	var raw []byte
	raw = append(raw, mrtRecord(TABLE_DUMP2, PEER_INDEX_TABLE, makePeerIndex(testPeer1, testPeer2))...)
	raw = append(raw, mrtRecord(TABLE_DUMP2, RIB_IPV4_UNICAST, makeRib(0, netip.MustParsePrefix("10.0.0.0/8"),
		makeRibEntry(0, shared), makeRibEntry(1, other)))...)
	raw = append(raw, mrtRecord(TABLE_DUMP2, RIB_IPV4_UNICAST, makeRib(1, netip.MustParsePrefix("10.128.0.0/9"),
		makeRibEntry(0, shared)))...)
	raw = append(raw, mrtRecord(TABLE_DUMP2, RIB_IPV4_UNICAST, makeRib(2, netip.MustParsePrefix("10.64.0.0/10"),
		makeRibEntry(0, shared)))...)

	msgs, br := tableReaderTest(t, raw)

	// peer1: one UPDATE with 3 bundled prefixes; peer2: one UPDATE
	require.Len(t, msgs, 2)
	require.Equal(t, uint64(2), br.Stats.Bundled)
	require.Equal(t, uint64(4), br.Stats.ParsedTable)

	for _, m := range msgs {
		require.Equal(t, msg.UPDATE, m.Type)
		u := &m.Update
		tags := pipe.GetTags(m)

		switch tags["PEER_AS"] {
		case "65001":
			require.Equal(t, "192.0.2.2", tags["PEER_IP"])
			require.Len(t, u.Reach, 3)
			require.Equal(t, "10.0.0.0/8", u.Reach[0].String())
			require.Equal(t, "10.128.0.0/9", u.Reach[1].String())
			require.Equal(t, "10.64.0.0/10", u.Reach[2].String())

			// attributes: AS4 path + next hop
			ap := u.Attrs.Get(attrs.ATTR_ASPATH).(*attrs.Aspath)
			require.Equal(t, []uint32{65000, 65001}, ap.Segments[0].List)
			nh := u.Attrs.Get(attrs.ATTR_NEXTHOP).(*attrs.IP)
			require.Equal(t, "192.0.2.1", nh.Addr.String())
		case "65002":
			require.Len(t, u.Reach, 1)
			ap := u.Attrs.Get(attrs.ATTR_ASPATH).(*attrs.Aspath)
			require.Equal(t, []uint32{65000, 65099}, ap.Segments[0].List)
		default:
			t.Fatalf("unexpected PEER_AS: %q", tags["PEER_AS"])
		}
	}
}

func TestTableReader_V2_AttrChange(t *testing.T) {
	var raw []byte
	raw = append(raw, mrtRecord(TABLE_DUMP2, PEER_INDEX_TABLE, makePeerIndex(testPeer1))...)
	raw = append(raw, mrtRecord(TABLE_DUMP2, RIB_IPV4_UNICAST, makeRib(0, netip.MustParsePrefix("10.0.0.0/8"),
		makeRibEntry(0, attrsV4(65001, 1))))...)
	raw = append(raw, mrtRecord(TABLE_DUMP2, RIB_IPV4_UNICAST, makeRib(1, netip.MustParsePrefix("20.0.0.0/8"),
		makeRibEntry(0, attrsV4(65002, 1))))...) // different attrs

	msgs, br := tableReaderTest(t, raw)
	require.Len(t, msgs, 2)
	require.Equal(t, uint64(0), br.Stats.Bundled)
	require.Len(t, msgs[0].Update.Reach, 1)
	require.Len(t, msgs[1].Update.Reach, 1)
}

func TestTableReader_V2_IPv6(t *testing.T) {
	nh := netip.MustParseAddr("2001:db8::1")
	pfx := netip.MustParsePrefix("2001:db8:1::/48")

	var raw []byte
	raw = append(raw, mrtRecord(TABLE_DUMP2, PEER_INDEX_TABLE, makePeerIndex(testPeer1))...)
	raw = append(raw, mrtRecord(TABLE_DUMP2, RIB_IPV6_UNICAST, makeRib(0, pfx,
		makeRibEntry(0, attrsV6(nh))))...)

	msgs, _ := tableReaderTest(t, raw)
	require.Len(t, msgs, 1)

	u := &msgs[0].Update
	require.Empty(t, u.Reach)
	mpp := u.ReachMP().Prefixes()
	require.NotNil(t, mpp)
	require.Equal(t, nh, mpp.NextHop)
	require.Len(t, mpp.Prefixes, 1)
	require.Equal(t, pfx, mpp.Prefixes[0].Prefix)
}

func TestTableReader_V2_IPv6Full(t *testing.T) {
	// full rfc4760 MP_REACH form: nexthop recovered, and the per-prefix
	// NLRI inside the attribute must not break aggregation
	nh := netip.MustParseAddr("2001:db8::1")
	pfx1 := netip.MustParsePrefix("2001:db8:1::/48")
	pfx2 := netip.MustParsePrefix("2001:db8:2::/48")

	var raw []byte
	raw = append(raw, mrtRecord(TABLE_DUMP2, PEER_INDEX_TABLE, makePeerIndex(testPeer1))...)
	raw = append(raw, mrtRecord(TABLE_DUMP2, RIB_IPV6_UNICAST, makeRib(0, pfx1,
		makeRibEntry(0, attrsV6Full(nh, pfx1))))...)
	raw = append(raw, mrtRecord(TABLE_DUMP2, RIB_IPV6_UNICAST, makeRib(1, pfx2,
		makeRibEntry(0, attrsV6Full(nh, pfx2))))...)

	msgs, br := tableReaderTest(t, raw)
	require.Len(t, msgs, 1)
	require.Equal(t, uint64(1), br.Stats.Bundled)

	mpp := msgs[0].Update.ReachMP().Prefixes()
	require.NotNil(t, mpp)
	require.Equal(t, nh, mpp.NextHop)
	require.Len(t, mpp.Prefixes, 2)
	require.Equal(t, pfx1, mpp.Prefixes[0].Prefix)
	require.Equal(t, pfx2, mpp.Prefixes[1].Prefix)
}

func TestTableReader_V1(t *testing.T) {
	ats := attrWK(1, 0)
	ats = append(ats, attrWK(2, 2, 1, 0xfd, 0xe8)...) // 2-byte AS 65000
	ats = append(ats, attrWK(3, 192, 0, 2, 1)...)

	body := appendUint16(nil, 0)
	body = appendUint16(body, 1)
	body = append(body, 10, 0, 0, 0)
	body = append(body, 8, 1)
	body = appendUint32(body, 1600000000)
	body = append(body, 192, 0, 2, 2)
	body = appendUint16(body, 65001)
	body = appendUint16(body, uint16(len(ats)))
	body = append(body, ats...)

	msgs, _ := tableReaderTest(t, mrtRecord(TABLE_DUMP, TD_IPV4, body))
	require.Len(t, msgs, 1)

	m := msgs[0]
	require.Equal(t, "65001", pipe.GetTags(m)["PEER_AS"])
	require.Len(t, m.Update.Reach, 1)
	require.Equal(t, "10.0.0.0/8", m.Update.Reach[0].String())

	// 2-byte AS path parsed correctly
	ap := m.Update.Attrs.Get(attrs.ATTR_ASPATH).(*attrs.Aspath)
	require.Equal(t, []uint32{65000}, ap.Segments[0].List)
}
