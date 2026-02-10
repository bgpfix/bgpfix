package caps

import (
	"testing"

	"github.com/bgpfix/bgpfix/afi"
	"github.com/stretchr/testify/require"
)

func TestMP_JSON(t *testing.T) {
	c := NewMP(CAP_MP).(*MP)
	c.Add(afi.AFI_IPV4, afi.SAFI_UNICAST)
	c.Add(afi.AFI_IPV6, afi.SAFI_UNICAST)

	buf := c.ToJSON(nil)
	require.Equal(t, `["IPV4/UNICAST","IPV6/UNICAST"]`, string(buf))

	c2 := NewMP(CAP_MP).(*MP)
	err := c2.FromJSON(buf)
	require.NoError(t, err)
	require.True(t, c2.Has(afi.AFI_IPV4, afi.SAFI_UNICAST))
	require.True(t, c2.Has(afi.AFI_IPV6, afi.SAFI_UNICAST))
}

func TestMP_Flowspec_JSON(t *testing.T) {
	c := NewMP(CAP_MP).(*MP)
	c.Add(afi.AFI_IPV4, afi.SAFI_FLOWSPEC)

	buf := c.ToJSON(nil)
	require.Equal(t, `["IPV4/FLOWSPEC"]`, string(buf))

	c2 := NewMP(CAP_MP).(*MP)
	err := c2.FromJSON(buf)
	require.NoError(t, err)
	require.True(t, c2.Has(afi.AFI_IPV4, afi.SAFI_FLOWSPEC))
}

func TestAS4_JSON(t *testing.T) {
	c := NewAS4(CAP_AS4).(*AS4)
	c.ASN = 4200000000

	buf := c.ToJSON(nil)
	require.Equal(t, "4200000000", string(buf))

	c2 := NewAS4(CAP_AS4).(*AS4)
	err := c2.FromJSON(buf)
	require.NoError(t, err)
	require.Equal(t, uint32(4200000000), c2.ASN)
}

func TestAddPath_JSON(t *testing.T) {
	c := NewAddPath(CAP_ADDPATH).(*AddPath)
	c.Add(afi.AS_IPV4_UNICAST, ADDPATH_SEND)

	buf := c.ToJSON(nil)
	require.Equal(t, `["IPV4/UNICAST/SEND"]`, string(buf))

	c2 := NewAddPath(CAP_ADDPATH).(*AddPath)
	err := c2.FromJSON(buf)
	require.NoError(t, err)
	require.True(t, c2.Has(afi.AS_IPV4_UNICAST, ADDPATH_SEND))
}

func TestAddPath_Bidir_JSON(t *testing.T) {
	c := NewAddPath(CAP_ADDPATH).(*AddPath)
	c.Add(afi.AS_IPV6_UNICAST, ADDPATH_BIDIR)

	buf := c.ToJSON(nil)
	require.Equal(t, `["IPV6/UNICAST/BIDIR"]`, string(buf))

	c2 := NewAddPath(CAP_ADDPATH).(*AddPath)
	err := c2.FromJSON(buf)
	require.NoError(t, err)
	require.True(t, c2.Has(afi.AS_IPV6_UNICAST, ADDPATH_SEND))
	require.True(t, c2.Has(afi.AS_IPV6_UNICAST, ADDPATH_RECEIVE))
}

func TestExtNH_JSON(t *testing.T) {
	c := NewExtNH(CAP_EXTENDED_NEXTHOP).(*ExtNH)
	c.Add(afi.AS_IPV4_UNICAST, afi.AFI_IPV6)

	buf := c.ToJSON(nil)
	require.Equal(t, `["IPV4/UNICAST/IPV6"]`, string(buf))

	c2 := NewExtNH(CAP_EXTENDED_NEXTHOP).(*ExtNH)
	err := c2.FromJSON(buf)
	require.NoError(t, err)
	require.True(t, c2.Has(afi.AS_IPV4_UNICAST, afi.AFI_IPV6))
}

func TestFQDN_JSON(t *testing.T) {
	c := NewFqdn(CAP_FQDN).(*Fqdn)
	c.Host = []byte("router1")
	c.Domain = []byte("example.com")

	buf := c.ToJSON(nil)
	require.Equal(t, `{"host":"router1","domain":"example.com"}`, string(buf))

	c2 := NewFqdn(CAP_FQDN).(*Fqdn)
	err := c2.FromJSON(buf)
	require.NoError(t, err)
	require.Equal(t, []byte("router1"), c2.Host)
	require.Equal(t, []byte("example.com"), c2.Domain)
}

func TestCaps_JSON(t *testing.T) {
	// build capabilities
	var cps Caps
	cps.Init()

	mp := cps.Use(CAP_MP).(*MP)
	mp.Add(afi.AFI_IPV4, afi.SAFI_UNICAST)

	as4 := cps.Use(CAP_AS4).(*AS4)
	as4.ASN = 65055

	cps.Use(CAP_ROUTE_REFRESH)

	buf := cps.ToJSON(nil)
	s := string(buf)

	// verify key structure
	require.Contains(t, s, `"MP":`)
	require.Contains(t, s, `"AS4":65055`)
	require.Contains(t, s, `"ROUTE_REFRESH":`)

	// round-trip
	var cps2 Caps
	cps2.Init()
	err := cps2.FromJSON(buf)
	require.NoError(t, err)
	require.True(t, cps2.Has(CAP_MP))
	require.True(t, cps2.Has(CAP_AS4))
	require.True(t, cps2.Has(CAP_ROUTE_REFRESH))
}

func TestCapCode_JSON(t *testing.T) {
	tests := []struct {
		code Code
		json string
	}{
		{CAP_MP, `"MP"`},
		{CAP_ROUTE_REFRESH, `"ROUTE_REFRESH"`},
		{CAP_EXTENDED_MESSAGE, `"EXTENDED_MESSAGE"`},
		{CAP_AS4, `"AS4"`},
		{CAP_ADDPATH, `"ADDPATH"`},
		{CAP_ROLE, `"ROLE"`},
		{CAP_FQDN, `"FQDN"`},
		{CAP_EXTENDED_NEXTHOP, `"EXTENDED_NEXTHOP"`},
		{CAP_GRACEFUL_RESTART, `"GRACEFUL_RESTART"`},
		{CAP_ENHANCED_ROUTE_REFRESH, `"ENHANCED_ROUTE_REFRESH"`},
		{CAP_LLGR, `"LLGR"`},
		{CAP_PRE_ROUTE_REFRESH, `"PRE_ROUTE_REFRESH"`},
	}

	for _, tt := range tests {
		t.Run(tt.json, func(t *testing.T) {
			buf := tt.code.ToJSON(nil)
			require.Equal(t, tt.json, string(buf))
		})
	}
}

func TestCapCode_Unknown_JSON(t *testing.T) {
	// unknown capability code should produce "CAP_N"
	buf := Code(200).ToJSON(nil)
	require.Equal(t, `"CAP_200"`, string(buf))
}
