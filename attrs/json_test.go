package attrs

import (
	"net/netip"
	"testing"

	"github.com/bgpfix/bgpfix/caps"
	"github.com/bgpfix/bgpfix/dir"
	"github.com/stretchr/testify/require"
)

func TestOrigin_JSON(t *testing.T) {
	tests := []struct {
		name   string
		origin byte
		json   string
	}{
		{"IGP", 0, `"IGP"`},
		{"EGP", 1, `"EGP"`},
		{"INCOMPLETE", 2, `"INCOMPLETE"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			at := NewAttr(ATTR_ORIGIN).(*Origin)
			at.Origin = tt.origin

			// ToJSON
			buf := at.ToJSON(nil)
			require.Equal(t, tt.json, string(buf))

			// FromJSON round-trip
			at2 := NewAttr(ATTR_ORIGIN).(*Origin)
			err := at2.FromJSON([]byte(tt.json))
			require.NoError(t, err)
			require.Equal(t, tt.origin, at2.Origin)
		})
	}
}

func TestU32_MED_JSON(t *testing.T) {
	at := NewAttr(ATTR_MED).(*U32)
	at.Val = 1000

	buf := at.ToJSON(nil)
	require.Equal(t, "1000", string(buf))

	at2 := NewAttr(ATTR_MED).(*U32)
	err := at2.FromJSON([]byte("1000"))
	require.NoError(t, err)
	require.Equal(t, uint32(1000), at2.Val)
}

func TestU32_LocalPref_JSON(t *testing.T) {
	at := NewAttr(ATTR_LOCALPREF).(*U32)
	at.Val = 200

	buf := at.ToJSON(nil)
	require.Equal(t, "200", string(buf))

	at2 := NewAttr(ATTR_LOCALPREF).(*U32)
	err := at2.FromJSON([]byte("200"))
	require.NoError(t, err)
	require.Equal(t, uint32(200), at2.Val)
}

func TestIP_NextHop_JSON(t *testing.T) {
	at := NewAttr(ATTR_NEXTHOP).(*IP)
	at.Addr = netip.MustParseAddr("192.0.2.1")

	buf := at.ToJSON(nil)
	require.Equal(t, `"192.0.2.1"`, string(buf))

	at2 := NewAttr(ATTR_NEXTHOP).(*IP)
	err := at2.FromJSON([]byte(`"192.0.2.1"`))
	require.NoError(t, err)
	require.Equal(t, netip.MustParseAddr("192.0.2.1"), at2.Addr)
}

func TestIPList_ClusterList_JSON(t *testing.T) {
	at := NewAttr(ATTR_CLUSTER_LIST).(*IPList)
	at.Addr = []netip.Addr{
		netip.MustParseAddr("10.0.0.1"),
		netip.MustParseAddr("10.0.0.2"),
	}

	buf := at.ToJSON(nil)
	require.Equal(t, `["10.0.0.1","10.0.0.2"]`, string(buf))

	at2 := NewAttr(ATTR_CLUSTER_LIST).(*IPList)
	err := at2.FromJSON([]byte(`["10.0.0.1","10.0.0.2"]`))
	require.NoError(t, err)
	require.Len(t, at2.Addr, 2)
	require.Equal(t, netip.MustParseAddr("10.0.0.1"), at2.Addr[0])
	require.Equal(t, netip.MustParseAddr("10.0.0.2"), at2.Addr[1])
}

func TestAggregator_JSON(t *testing.T) {
	at := NewAttr(ATTR_AGGREGATOR).(*Aggregator)
	at.ASN = 65001
	at.Addr = netip.MustParseAddr("198.51.100.1")

	buf := at.ToJSON(nil)
	require.Equal(t, `{"asn":65001, "addr":"198.51.100.1"}`, string(buf))

	at2 := NewAttr(ATTR_AGGREGATOR).(*Aggregator)
	err := at2.FromJSON(buf)
	require.NoError(t, err)
	require.Equal(t, uint32(65001), at2.ASN)
	require.Equal(t, netip.MustParseAddr("198.51.100.1"), at2.Addr)
}

func TestAspath_Sequence_JSON(t *testing.T) {
	at := NewAttr(ATTR_ASPATH).(*Aspath)
	var cps caps.Caps
	cps.Use(caps.CAP_AS4)

	// AS_SEQUENCE: [64515, 20473, 15169]
	err := at.Unmarshal([]byte{
		0x02, 0x03, // SEQUENCE of 3
		0x00, 0x00, 0xFC, 0x03, // 64515
		0x00, 0x00, 0x4F, 0xF9, // 20473
		0x00, 0x00, 0x3B, 0x41, // 15169
	}, cps, dir.DIR_L)
	require.NoError(t, err)

	buf := at.ToJSON(nil)
	require.Equal(t, "[64515,20473,15169]", string(buf))

	at2 := NewAttr(ATTR_ASPATH).(*Aspath)
	err = at2.FromJSON([]byte("[64515,20473,15169]"))
	require.NoError(t, err)
	require.Equal(t, 3, at2.Len())
}

func TestAspath_WithSet_JSON(t *testing.T) {
	at := NewAttr(ATTR_ASPATH).(*Aspath)
	at.Segments = []AspathSegment{
		{IsSet: false, List: []uint32{64515}},
		{IsSet: true, List: []uint32{20473, 15169}},
	}

	buf := at.ToJSON(nil)
	require.Equal(t, "[64515,[20473,15169]]", string(buf))

	at2 := NewAttr(ATTR_ASPATH).(*Aspath)
	err := at2.FromJSON([]byte("[64515,[20473,15169]]"))
	require.NoError(t, err)
	require.Len(t, at2.Segments, 2)
	require.False(t, at2.Segments[0].IsSet)
	require.True(t, at2.Segments[1].IsSet)
}

func TestAspath_Empty_JSON(t *testing.T) {
	at := NewAttr(ATTR_ASPATH).(*Aspath)

	buf := at.ToJSON(nil)
	require.Equal(t, "[]", string(buf))

	at2 := NewAttr(ATTR_ASPATH).(*Aspath)
	err := at2.FromJSON([]byte("[]"))
	require.NoError(t, err)
	require.Equal(t, 0, at2.Len())
}

func TestCommunity_JSON(t *testing.T) {
	at := NewAttr(ATTR_COMMUNITY).(*Community)
	var cps caps.Caps

	// AS100:1, AS200:2
	err := at.Unmarshal([]byte{
		0x00, 0x64, 0x00, 0x01,
		0x00, 0xC8, 0x00, 0x02,
	}, cps, dir.DIR_L)
	require.NoError(t, err)

	buf := at.ToJSON(nil)
	require.Equal(t, `["100:1","200:2"]`, string(buf))

	at2 := NewAttr(ATTR_COMMUNITY).(*Community)
	err = at2.FromJSON([]byte(`["100:1","200:2"]`))
	require.NoError(t, err)
	require.Equal(t, 2, at2.Len())
	require.Equal(t, uint16(100), at2.ASN[0])
	require.Equal(t, uint16(1), at2.Value[0])
}

func TestLargeCommunity_JSON(t *testing.T) {
	at := NewAttr(ATTR_LARGE_COMMUNITY).(*LargeCom)
	var cps caps.Caps

	// AS65001:100:200
	err := at.Unmarshal([]byte{
		0x00, 0x00, 0xFD, 0xE9, // 65001
		0x00, 0x00, 0x00, 0x64, // 100
		0x00, 0x00, 0x00, 0xC8, // 200
	}, cps, dir.DIR_L)
	require.NoError(t, err)

	buf := at.ToJSON(nil)
	require.Equal(t, `["65001:100:200"]`, string(buf))

	at2 := NewAttr(ATTR_LARGE_COMMUNITY).(*LargeCom)
	err = at2.FromJSON([]byte(`["65001:100:200"]`))
	require.NoError(t, err)
	require.Equal(t, 1, at2.Len())
	require.Equal(t, uint32(65001), at2.ASN[0])
	require.Equal(t, uint32(100), at2.Value1[0])
	require.Equal(t, uint32(200), at2.Value2[0])
}

func TestExtCommunity_RT_JSON(t *testing.T) {
	at := NewAttr(ATTR_EXT_COMMUNITY).(*Extcom)
	var cps caps.Caps

	// Route Target 64645:53000 (AS2 type, transitive)
	err := at.Unmarshal([]byte{
		0x00, 0x02, 0xFC, 0x85, 0x00, 0x00, 0xCF, 0x08,
	}, cps, dir.DIR_L)
	require.NoError(t, err)

	buf := at.ToJSON(nil)
	// type should be "TARGET" (AS2_TARGET with EXTCOM_ prefix stripped)
	require.Contains(t, string(buf), `"type":"TARGET"`)
	require.Contains(t, string(buf), `"value":"64645:53000"`)
	// transitive, so no nontransitive field
	require.NotContains(t, string(buf), "nontransitive")

	// round-trip
	at2 := NewAttr(ATTR_EXT_COMMUNITY).(*Extcom)
	err = at2.FromJSON(buf)
	require.NoError(t, err)
	require.Equal(t, 1, at2.Len())
}

func TestExtCommunity_FlowRate_JSON(t *testing.T) {
	at := NewAttr(ATTR_EXT_COMMUNITY).(*Extcom)
	var cps caps.Caps

	// FLOW_RATE_BYTES with rate=0 (drop traffic)
	// type=0x8006, value: id=0(2bytes) + rate=0.0(float32)
	err := at.Unmarshal([]byte{
		0x80, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}, cps, dir.DIR_L)
	require.NoError(t, err)

	buf := at.ToJSON(nil)
	require.Contains(t, string(buf), `"type":"FLOW_RATE_BYTES"`)
	require.Contains(t, string(buf), `"value":0`)
}

func TestOTC_JSON_RoundTrip(t *testing.T) {
	at := NewAttr(ATTR_OTC).(*U32)
	at.Val = 65001

	buf := at.ToJSON(nil)
	require.Equal(t, "65001", string(buf))

	at2 := NewAttr(ATTR_OTC).(*U32)
	err := at2.FromJSON(buf)
	require.NoError(t, err)
	require.Equal(t, uint32(65001), at2.Val)
}
