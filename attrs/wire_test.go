package attrs

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
