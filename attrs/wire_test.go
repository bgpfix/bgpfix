package attrs

// Some test data in this file is derived from routecore (https://github.com/NLnetLabs/routecore)
// Copyright (c) 2021, NLnet Labs. All rights reserved.
// Licensed under the BSD 3-Clause License.
// See https://github.com/NLnetLabs/routecore/blob/main/LICENSE

import (
	"net/netip"
	"testing"

	"github.com/bgpfix/bgpfix/afi"
	"github.com/bgpfix/bgpfix/caps"
	"github.com/bgpfix/bgpfix/dir"
	"github.com/stretchr/testify/require"
)

func TestOrigin_Wire(t *testing.T) {
	at := NewAttr(ATTR_ORIGIN).(*Origin)
	var cps caps.Caps

	err := at.Unmarshal([]byte{0x00}, cps, dir.DIR_L)
	require.NoError(t, err)
	require.Equal(t, byte(0), at.Origin)

	buf := at.Marshal(nil, cps, dir.DIR_L)
	require.Equal(t, []byte{0x40, 0x01, 0x01, 0x00}, buf)
}

func TestU32_Wire(t *testing.T) {
	at := NewAttr(ATTR_MED).(*U32)
	var cps caps.Caps

	err := at.Unmarshal([]byte{0x00, 0x00, 0x03, 0xE8}, cps, dir.DIR_L)
	require.NoError(t, err)
	require.Equal(t, uint32(1000), at.Val)

	buf := at.Marshal(nil, cps, dir.DIR_L)
	require.Equal(t, []byte{0x80, 0x04, 0x04, 0x00, 0x00, 0x03, 0xE8}, buf)
}

func TestNextHop_Wire(t *testing.T) {
	at := NewAttr(ATTR_NEXTHOP).(*IP)
	var cps caps.Caps

	err := at.Unmarshal([]byte{192, 0, 2, 1}, cps, dir.DIR_L)
	require.NoError(t, err)
	require.Equal(t, netip.AddrFrom4([4]byte{192, 0, 2, 1}), at.Addr)

	buf := at.Marshal(nil, cps, dir.DIR_L)
	require.Equal(t, []byte{0x40, 0x03, 0x04, 192, 0, 2, 1}, buf)
}

func TestAspath_Wire(t *testing.T) {
	at := NewAttr(ATTR_ASPATH).(*Aspath)
	var cps caps.Caps

	err := at.Unmarshal([]byte{0x02, 0x02, 0xFD, 0xE9, 0x00, 0x64}, cps, dir.DIR_L)
	require.NoError(t, err)
	require.Equal(t, 2, at.Len())

	buf := at.Marshal(nil, cps, dir.DIR_L)
	require.Equal(t, []byte{0x40, 0x02, 0x06, 0x02, 0x02, 0xFD, 0xE9, 0x00, 0x64}, buf)
}

func TestAspath_AS4_Wire(t *testing.T) {
	at := NewAttr(ATTR_ASPATH).(*Aspath)
	var cps caps.Caps
	cps.Use(caps.CAP_AS4)

	err := at.Unmarshal([]byte{0x02, 0x01, 0x00, 0x00, 0xFD, 0xE9}, cps, dir.DIR_L)
	require.NoError(t, err)
	require.Equal(t, uint32(65001), at.Segments[0].List[0])

	buf := at.Marshal(nil, cps, dir.DIR_L)
	require.Equal(t, []byte{0x40, 0x02, 0x06, 0x02, 0x01, 0x00, 0x00, 0xFD, 0xE9}, buf)
}

func TestAggregator_AS4_Wire(t *testing.T) {
	at := NewAttr(ATTR_AGGREGATOR).(*Aggregator)
	var cps caps.Caps
	cps.Use(caps.CAP_AS4)

	err := at.Unmarshal([]byte{0x00, 0x00, 0xFD, 0xE9, 192, 0, 2, 1}, cps, dir.DIR_L)
	require.NoError(t, err)
	require.Equal(t, uint32(65001), at.ASN)
	require.Equal(t, netip.AddrFrom4([4]byte{192, 0, 2, 1}), at.Addr)

	buf := at.Marshal(nil, cps, dir.DIR_L)
	require.Equal(t, []byte{0xC0, 0x07, 0x08, 0x00, 0x00, 0xFD, 0xE9, 192, 0, 2, 1}, buf)
}

func TestCommunity_Wire(t *testing.T) {
	at := NewAttr(ATTR_COMMUNITY).(*Community)
	var cps caps.Caps

	err := at.Unmarshal([]byte{0x00, 0x64, 0x00, 0x01, 0x00, 0xC8, 0x00, 0x02}, cps, dir.DIR_L)
	require.NoError(t, err)
	require.Equal(t, 2, at.Len())

	buf := at.Marshal(nil, cps, dir.DIR_L)
	require.Equal(t, []byte{0xC0, 0x08, 0x08, 0x00, 0x64, 0x00, 0x01, 0x00, 0xC8, 0x00, 0x02}, buf)
}

func TestLargeCommunity_Wire(t *testing.T) {
	at := NewAttr(ATTR_LARGE_COMMUNITY).(*LargeCom)
	var cps caps.Caps

	err := at.Unmarshal([]byte{
		0x00, 0x00, 0xFD, 0xE9,
		0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x02,
	}, cps, dir.DIR_L)
	require.NoError(t, err)
	require.Equal(t, 1, at.Len())

	buf := at.Marshal(nil, cps, dir.DIR_L)
	require.Equal(t, []byte{0xC0, 0x20, 0x0C, 0x00, 0x00, 0xFD, 0xE9, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02}, buf)
}

func TestMPReachUnreach_Wire(t *testing.T) {
	var cps caps.Caps

	// MP_REACH for 10.0.0.0/8 with NH 192.0.2.1
	atr := NewAttr(ATTR_MP_REACH).(*MP)
	reachVal := []byte{0x00, 0x01, 0x01, 0x04, 192, 0, 2, 1, 0x00, 0x08, 10}
	err := atr.Unmarshal(reachVal, cps, dir.DIR_L)
	require.NoError(t, err)
	require.Equal(t, afi.AS_IPV4_UNICAST, atr.AS)
	require.Equal(t, []byte{192, 0, 2, 1}, atr.NH)
	require.Equal(t, []byte{0x08, 10}, atr.Data)
	require.NotNil(t, atr.Prefixes())
	require.Equal(t, 1, atr.Prefixes().Len())

	reachBuf := atr.Marshal(nil, cps, dir.DIR_L)
	require.Equal(t, []byte{0x80, 0x0E, 0x0B, 0x00, 0x01, 0x01, 0x04, 192, 0, 2, 1, 0x00, 0x08, 10}, reachBuf)

	// MP_UNREACH for 10.0.0.0/8
	atu := NewAttr(ATTR_MP_UNREACH).(*MP)
	unreachVal := []byte{0x00, 0x01, 0x01, 0x08, 10}
	err = atu.Unmarshal(unreachVal, cps, dir.DIR_L)
	require.NoError(t, err)
	require.Equal(t, afi.AS_IPV4_UNICAST, atu.AS)
	require.Equal(t, []byte{0x08, 10}, atu.Data)
	require.NotNil(t, atu.Prefixes())
	require.Equal(t, 1, atu.Prefixes().Len())

	unreachBuf := atu.Marshal(nil, cps, dir.DIR_L)
	require.Equal(t, []byte{0x80, 0x0F, 0x05, 0x00, 0x01, 0x01, 0x08, 10}, unreachBuf)
}

func TestAspath_EmptyPath_Wire(t *testing.T) {
	at := NewAttr(ATTR_ASPATH).(*Aspath)
	var cps caps.Caps

	// Empty AS_PATH (common for iBGP)
	err := at.Unmarshal([]byte{}, cps, dir.DIR_L)
	require.NoError(t, err)
	require.Equal(t, 0, at.Len())

	buf := at.Marshal(nil, cps, dir.DIR_L)
	require.Equal(t, []byte{0x40, 0x02, 0x00}, buf)
}

func TestAspath_ASSet_Wire(t *testing.T) {
	at := NewAttr(ATTR_ASPATH).(*Aspath)
	var cps caps.Caps

	// AS_SET (type=1) with 2 ASNs
	err := at.Unmarshal([]byte{0x01, 0x02, 0x00, 0x64, 0x00, 0xC8}, cps, dir.DIR_L)
	require.NoError(t, err)
	require.Len(t, at.Segments, 1)
	require.True(t, at.Segments[0].IsSet)
	require.Equal(t, []uint32{100, 200}, at.Segments[0].List)
}

func TestOrigin_AllValues_Wire(t *testing.T) {
	var cps caps.Caps

	tests := []struct {
		name   string
		value  byte
		expect byte
	}{
		{"IGP", 0x00, 0x00},
		{"EGP", 0x01, 0x01},
		{"INCOMPLETE", 0x02, 0x02},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			at := NewAttr(ATTR_ORIGIN).(*Origin)
			err := at.Unmarshal([]byte{tt.value}, cps, dir.DIR_L)
			require.NoError(t, err)
			require.Equal(t, tt.expect, at.Origin)
		})
	}
}

func TestCommunity_WellKnown_Wire(t *testing.T) {
	at := NewAttr(ATTR_COMMUNITY).(*Community)
	var cps caps.Caps

	// NO_EXPORT (0xFFFFFF01)
	err := at.Unmarshal([]byte{0xFF, 0xFF, 0xFF, 0x01}, cps, dir.DIR_L)
	require.NoError(t, err)
	require.Equal(t, uint16(0xFFFF), at.ASN[0])
	require.Equal(t, uint16(0xFF01), at.Value[0])
}

func TestRaw_Attr_Wire(t *testing.T) {
	at := NewAttr(ATTR_SET).(*Raw)
	var cps caps.Caps

	err := at.Unmarshal([]byte{0xDE, 0xAD, 0xBE, 0xEF}, cps, dir.DIR_L)
	require.NoError(t, err)
	require.Equal(t, []byte{0xDE, 0xAD, 0xBE, 0xEF}, at.Raw)
}

// Tests below based on routecore test data for comprehensive wire format coverage

func TestAspath_4Byte_Sequence_Wire(t *testing.T) {
	// From routecore: AS_PATH with 4-byte AS_SEQUENCE(AS100, AS200)
	at := NewAttr(ATTR_ASPATH).(*Aspath)
	var cps caps.Caps
	cps.Use(caps.CAP_AS4)

	// AS_SEQUENCE of length 2: AS100, AS200
	err := at.Unmarshal([]byte{
		0x02, 0x02, // SEQUENCE of length 2
		0x00, 0x00, 0x00, 100,
		0x00, 0x00, 0x00, 200,
	}, cps, dir.DIR_L)
	require.NoError(t, err)
	require.Len(t, at.Segments, 1)
	require.False(t, at.Segments[0].IsSet)
	require.Equal(t, []uint32{100, 200}, at.Segments[0].List)

	buf := at.Marshal(nil, cps, dir.DIR_L)
	require.Equal(t, []byte{
		0x40, 0x02, 10,
		0x02, 0x02,
		0x00, 0x00, 0x00, 100,
		0x00, 0x00, 0x00, 200,
	}, buf)
}

func TestAggregator_Routecore_Wire(t *testing.T) {
	// From routecore: Aggregator with AS101, IP 198.51.100.1
	at := NewAttr(ATTR_AGGREGATOR).(*Aggregator)
	var cps caps.Caps
	cps.Use(caps.CAP_AS4)

	err := at.Unmarshal([]byte{
		0x00, 0x00, 0x00, 0x65, // AS101
		0xc6, 0x33, 0x64, 0x01, // 198.51.100.1
	}, cps, dir.DIR_L)
	require.NoError(t, err)
	require.Equal(t, uint32(101), at.ASN)
	require.Equal(t, netip.MustParseAddr("198.51.100.1"), at.Addr)

	buf := at.Marshal(nil, cps, dir.DIR_L)
	require.Equal(t, []byte{
		0xc0, 0x07, 0x08,
		0x00, 0x00, 0x00, 0x65,
		0xc6, 0x33, 0x64, 0x01,
	}, buf)
}

func TestU32_MED_Max_Wire(t *testing.T) {
	// Test MED with max value 255 (from routecore)
	at := NewAttr(ATTR_MED).(*U32)
	var cps caps.Caps

	err := at.Unmarshal([]byte{0x00, 0x00, 0x00, 0xff}, cps, dir.DIR_L)
	require.NoError(t, err)
	require.Equal(t, uint32(255), at.Val)

	buf := at.Marshal(nil, cps, dir.DIR_L)
	require.Equal(t, []byte{0x80, 0x04, 0x04, 0x00, 0x00, 0x00, 0xff}, buf)
}

func TestU32_LocalPref_Wire(t *testing.T) {
	// From routecore: LOCAL_PREF with value 10
	at := NewAttr(ATTR_LOCALPREF).(*U32)
	var cps caps.Caps

	err := at.Unmarshal([]byte{0x00, 0x00, 0x00, 0x0a}, cps, dir.DIR_L)
	require.NoError(t, err)
	require.Equal(t, uint32(10), at.Val)

	buf := at.Marshal(nil, cps, dir.DIR_L)
	require.Equal(t, []byte{0x40, 0x05, 0x04, 0x00, 0x00, 0x00, 0x0a}, buf)
}

func TestAtomicAggregate_Wire(t *testing.T) {
	// From routecore: ATOMIC_AGGREGATE (empty value)
	at := NewAttr(ATTR_AGGREGATE).(*Raw)
	var cps caps.Caps

	err := at.Unmarshal([]byte{}, cps, dir.DIR_L)
	require.NoError(t, err)
	require.Empty(t, at.Raw)

	buf := at.Marshal(nil, cps, dir.DIR_L)
	require.Equal(t, []byte{0x40, 0x06, 0x00}, buf)
}

func TestCommunity_MultiValue_Routecore_Wire(t *testing.T) {
	// From routecore: Multiple communities including well-known
	at := NewAttr(ATTR_COMMUNITY).(*Community)
	var cps caps.Caps

	// AS42:518, NO_EXPORT, NO_ADVERTISE, NO_EXPORT_SUBCONFED
	err := at.Unmarshal([]byte{
		0x00, 0x2a, 0x02, 0x06, // AS42:518
		0xff, 0xff, 0xff, 0x01, // NO_EXPORT
		0xff, 0xff, 0xff, 0x02, // NO_ADVERTISE
		0xff, 0xff, 0xff, 0x03, // NO_EXPORT_SUBCONFED
	}, cps, dir.DIR_L)
	require.NoError(t, err)
	require.Equal(t, 4, at.Len())

	buf := at.Marshal(nil, cps, dir.DIR_L)
	require.Equal(t, []byte{
		0xc0, 0x08, 0x10,
		0x00, 0x2a, 0x02, 0x06,
		0xff, 0xff, 0xff, 0x01,
		0xff, 0xff, 0xff, 0x02,
		0xff, 0xff, 0xff, 0x03,
	}, buf)
}

func TestOriginatorID_Wire(t *testing.T) {
	// From routecore: ORIGINATOR_ID 10.0.0.4
	at := NewAttr(ATTR_ORIGINATOR).(*IP)
	var cps caps.Caps

	err := at.Unmarshal([]byte{0x0a, 0x00, 0x00, 0x04}, cps, dir.DIR_L)
	require.NoError(t, err)
	require.Equal(t, netip.MustParseAddr("10.0.0.4"), at.Addr)

	buf := at.Marshal(nil, cps, dir.DIR_L)
	require.Equal(t, []byte{0x80, 0x09, 0x04, 0x0a, 0x00, 0x00, 0x04}, buf)
}

func TestClusterList_Wire(t *testing.T) {
	// From routecore: CLUSTER_LIST with single cluster 10.0.0.3
	at := NewAttr(ATTR_CLUSTER_LIST).(*IPList)
	var cps caps.Caps

	err := at.Unmarshal([]byte{0x0a, 0x00, 0x00, 0x03}, cps, dir.DIR_L)
	require.NoError(t, err)
	require.Len(t, at.Addr, 1)
	require.Equal(t, netip.MustParseAddr("10.0.0.3"), at.Addr[0])

	buf := at.Marshal(nil, cps, dir.DIR_L)
	require.Equal(t, []byte{0x80, 0x0a, 0x04, 0x0a, 0x00, 0x00, 0x03}, buf)
}

func TestAS4Path_Wire(t *testing.T) {
	// From routecore: AS4_PATH with AS_SEQUENCE(AS100, AS200)
	at := NewAttr(ATTR_AS4PATH).(*Aspath)
	var cps caps.Caps
	cps.Use(caps.CAP_AS4) // AS4_PATH always uses 4-byte ASNs

	err := at.Unmarshal([]byte{
		0x02, 0x02, // SEQUENCE of length 2
		0x00, 0x00, 0x00, 100,
		0x00, 0x00, 0x00, 200,
	}, cps, dir.DIR_L)
	require.NoError(t, err)
	require.Len(t, at.Segments, 1)
	require.Equal(t, []uint32{100, 200}, at.Segments[0].List)

	buf := at.Marshal(nil, cps, dir.DIR_L)
	// bgpfix uses 0x80 (optional) for AS4_PATH by default
	require.Equal(t, []byte{
		0x80, 0x11, 10,
		0x02, 0x02,
		0x00, 0x00, 0x00, 100,
		0x00, 0x00, 0x00, 200,
	}, buf)
}

func TestAS4Aggregator_Wire(t *testing.T) {
	// From routecore: AS4_AGGREGATOR AS1234, IP 10.0.0.99
	at := NewAttr(ATTR_AS4AGGREGATOR).(*Aggregator)
	var cps caps.Caps

	err := at.Unmarshal([]byte{
		0x00, 0x00, 0x04, 0xd2, // AS1234
		10, 0, 0, 99, // 10.0.0.99
	}, cps, dir.DIR_L)
	require.NoError(t, err)
	require.Equal(t, uint32(1234), at.ASN)
	require.Equal(t, netip.MustParseAddr("10.0.0.99"), at.Addr)

	buf := at.Marshal(nil, cps, dir.DIR_L)
	// bgpfix uses 0x80 (optional) for AS4_AGGREGATOR by default
	require.Equal(t, []byte{
		0x80, 0x12, 0x08,
		0x00, 0x00, 0x04, 0xd2,
		10, 0, 0, 99,
	}, buf)
}

func TestLargeCommunity_Multi_Wire(t *testing.T) {
	// From routecore: Multiple large communities
	at := NewAttr(ATTR_LARGE_COMMUNITY).(*LargeCom)
	var cps caps.Caps

	// AS8283:6:15, AS57866:100:2914, AS57866:101:100, AS57866:103:1, AS57866:104:31
	err := at.Unmarshal([]byte{
		0x00, 0x00, 0x20, 0x5b, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x0f,
		0x00, 0x00, 0xe2, 0x0a, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x0b, 0x62,
		0x00, 0x00, 0xe2, 0x0a, 0x00, 0x00, 0x00, 0x65, 0x00, 0x00, 0x00, 0x64,
		0x00, 0x00, 0xe2, 0x0a, 0x00, 0x00, 0x00, 0x67, 0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0xe2, 0x0a, 0x00, 0x00, 0x00, 0x68, 0x00, 0x00, 0x00, 0x1f,
	}, cps, dir.DIR_L)
	require.NoError(t, err)
	require.Equal(t, 5, at.Len())
	require.Equal(t, uint32(8283), at.ASN[0])
	require.Equal(t, uint32(6), at.Value1[0])
	require.Equal(t, uint32(15), at.Value2[0])
}

func TestOTC_Wire(t *testing.T) {
	// From routecore: OTC (Only To Customer) with AS1234
	// Note: In bgpfix, ATTR_OTC is treated as Raw since no specific handler is registered
	at := NewAttr(ATTR_OTC).(*Raw)
	var cps caps.Caps

	err := at.Unmarshal([]byte{0x00, 0x00, 0x04, 0xd2}, cps, dir.DIR_L)
	require.NoError(t, err)
	require.Equal(t, []byte{0x00, 0x00, 0x04, 0xd2}, at.Raw)

	buf := at.Marshal(nil, cps, dir.DIR_L)
	require.Equal(t, []byte{0x80, 0x23, 0x04, 0x00, 0x00, 0x04, 0xd2}, buf)
}

func TestMPReachIPv6_Wire(t *testing.T) {
	// IPv6 unicast MP_REACH with link-local next-hop
	at := NewAttr(ATTR_MP_REACH).(*MP)
	var cps caps.Caps

	// AFI=2 (IPv6), SAFI=1 (unicast), NH len=32 (global + link-local)
	// Global NH: fc00:10:1:10::10, Link-local: fe80::10
	// NLRI: fc00::10/128
	err := at.Unmarshal([]byte{
		0x00, 0x02, 0x01, // AFI=2, SAFI=1
		0x20, // NH len = 32
		// Global NH: fc00:10:1:10::10
		0xfc, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00, 0x10,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
		// Link-local: fe80::10
		0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
		0x00, // Reserved
		// NLRI: fc00::10/128
		0x80,
		0xfc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
	}, cps, dir.DIR_L)
	require.NoError(t, err)
	require.Equal(t, afi.AS_IPV6_UNICAST, at.AS)
	require.Len(t, at.NH, 32)
}

func TestMPUnreachIPv6Multi_Wire(t *testing.T) {
	// IPv6 MP_UNREACH with 4 prefixes (unicast)
	at := NewAttr(ATTR_MP_UNREACH).(*MP)
	var cps caps.Caps

	// AFI=2 (IPv6), SAFI=1 (unicast)
	// Withdrawals: 4x /64 prefixes
	err := at.Unmarshal([]byte{
		0x00, 0x02, 0x01, // AFI=2, SAFI=1 (unicast)
		// 2001:db8:ffff::/64
		0x40, 0x20, 0x01, 0x0d, 0xb8, 0xff, 0xff, 0x00, 0x00,
		// 2001:db8:ffff:1::/64
		0x40, 0x20, 0x01, 0x0d, 0xb8, 0xff, 0xff, 0x00, 0x01,
		// 2001:db8:ffff:2::/64
		0x40, 0x20, 0x01, 0x0d, 0xb8, 0xff, 0xff, 0x00, 0x02,
		// 2001:db8:ffff:3::/64
		0x40, 0x20, 0x01, 0x0d, 0xb8, 0xff, 0xff, 0x00, 0x03,
	}, cps, dir.DIR_L)
	require.NoError(t, err)
	require.Equal(t, afi.AS_IPV6_UNICAST, at.AS)
	prefs := at.Prefixes()
	require.NotNil(t, prefs)
	require.Equal(t, 4, prefs.Len())
}

func TestNextHop_Routecore_Wire(t *testing.T) {
	// From routecore: NEXT_HOP 1.2.3.4
	at := NewAttr(ATTR_NEXTHOP).(*IP)
	var cps caps.Caps

	err := at.Unmarshal([]byte{0x01, 0x02, 0x03, 0x04}, cps, dir.DIR_L)
	require.NoError(t, err)
	require.Equal(t, netip.MustParseAddr("1.2.3.4"), at.Addr)

	buf := at.Marshal(nil, cps, dir.DIR_L)
	require.Equal(t, []byte{0x40, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04}, buf)
}

func TestExtendedCommunity_RT_Wire(t *testing.T) {
	// From routecore: Route Target extended community rt:64645:53000
	at := NewAttr(ATTR_EXT_COMMUNITY).(*Extcom)
	var cps caps.Caps

	err := at.Unmarshal([]byte{
		0x00, 0x02, 0xfc, 0x85, 0x00, 0x00, 0xcf, 0x08,
	}, cps, dir.DIR_L)
	require.NoError(t, err)
	require.Equal(t, 1, at.Len())

	buf := at.Marshal(nil, cps, dir.DIR_L)
	require.Equal(t, []byte{
		0xc0, 0x10, 0x08,
		0x00, 0x02, 0xfc, 0x85, 0x00, 0x00, 0xcf, 0x08,
	}, buf)
}

// Error case tests

func TestOrigin_InvalidLength_Wire(t *testing.T) {
	at := NewAttr(ATTR_ORIGIN).(*Origin)
	var cps caps.Caps

	// Origin must be exactly 1 byte
	err := at.Unmarshal([]byte{0x00, 0x00}, cps, dir.DIR_L)
	require.Error(t, err)

	err = at.Unmarshal([]byte{}, cps, dir.DIR_L)
	require.Error(t, err)
}

func TestU32_InvalidLength_Wire(t *testing.T) {
	at := NewAttr(ATTR_MED).(*U32)
	var cps caps.Caps

	// MED must be exactly 4 bytes
	err := at.Unmarshal([]byte{0x00, 0x00, 0x00}, cps, dir.DIR_L)
	require.Error(t, err)

	err = at.Unmarshal([]byte{0x00, 0x00, 0x00, 0x00, 0x00}, cps, dir.DIR_L)
	require.Error(t, err)
}

func TestNextHop_InvalidLength_Wire(t *testing.T) {
	at := NewAttr(ATTR_NEXTHOP).(*IP)
	var cps caps.Caps

	// NEXT_HOP must be exactly 4 bytes for IPv4
	err := at.Unmarshal([]byte{0x01, 0x02, 0x03}, cps, dir.DIR_L)
	require.Error(t, err)
}
