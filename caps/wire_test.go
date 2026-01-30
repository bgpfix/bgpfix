package caps

import (
	"testing"

	"github.com/bgpfix/bgpfix/afi"
	"github.com/stretchr/testify/require"
)

func TestMP_Wire(t *testing.T) {
	c := NewMP(CAP_MP).(*MP)
	var cps Caps

	err := c.Unmarshal([]byte{0x00, 0x01, 0x00, 0x01}, cps)
	require.NoError(t, err)
	require.True(t, c.Has(afi.AFI_IPV4, afi.SAFI_UNICAST))

	buf := c.Marshal(nil)
	require.Equal(t, []byte{byte(CAP_MP), 4, 0x00, 0x01, 0x00, 0x01}, buf)
}

func TestAS4_Wire(t *testing.T) {
	c := NewAS4(CAP_AS4).(*AS4)
	var cps Caps

	err := c.Unmarshal([]byte{0x00, 0x00, 0xFD, 0xE9}, cps)
	require.NoError(t, err)
	require.Equal(t, uint32(65001), c.ASN)

	buf := c.Marshal(nil)
	require.Equal(t, []byte{byte(CAP_AS4), 4, 0x00, 0x00, 0xFD, 0xE9}, buf)

	err = c.Unmarshal([]byte{0x00}, cps)
	require.ErrorIs(t, err, ErrLength)
}

func TestAddPath_Wire(t *testing.T) {
	c := NewAddPath(CAP_ADDPATH).(*AddPath)
	var cps Caps

	err := c.Unmarshal([]byte{0x00, 0x01, 0x01, byte(ADDPATH_SEND)}, cps)
	require.NoError(t, err)
	require.True(t, c.Has(afi.AS_IPV4_UNICAST, ADDPATH_SEND))

	buf := c.Marshal(nil)
	require.Equal(t, []byte{byte(CAP_ADDPATH), 4, 0x00, 0x01, 0x01, byte(ADDPATH_SEND)}, buf)

	err = c.Unmarshal([]byte{0x00, 0x01, 0x01, 0x00}, cps)
	require.ErrorIs(t, err, ErrValue)
}

func TestExtNH_Wire(t *testing.T) {
	c := NewExtNH(CAP_EXTENDED_NEXTHOP).(*ExtNH)
	var cps Caps

	err := c.Unmarshal([]byte{0x00, 0x01, 0x00, 0x01, 0x00, 0x02}, cps)
	require.NoError(t, err)
	require.True(t, c.Has(afi.AS_IPV4_UNICAST, afi.AFI_IPV6))

	buf := c.Marshal(nil)
	require.Equal(t, []byte{byte(CAP_EXTENDED_NEXTHOP), 6, 0x00, 0x01, 0x00, 0x01, 0x00, 0x02}, buf)

	err = c.Unmarshal([]byte{0x00, 0x01}, cps)
	require.ErrorIs(t, err, ErrLength)
}

func TestFQDN_Wire(t *testing.T) {
	c := NewFqdn(CAP_FQDN).(*Fqdn)
	var cps Caps

	err := c.Unmarshal([]byte{0x04, 'b', 'g', 'p', 'd', 0x03, 'n', 'e', 't'}, cps)
	require.NoError(t, err)
	require.Equal(t, []byte("bgpd"), c.Host)
	require.Equal(t, []byte("net"), c.Domain)

	buf := c.Marshal(nil)
	require.Equal(t, []byte{byte(CAP_FQDN), 9, 0x04, 'b', 'g', 'p', 'd', 0x03, 'n', 'e', 't'}, buf)

	err = c.Unmarshal([]byte{0x04, 'b', 'g'}, cps)
	require.ErrorIs(t, err, ErrLength)
}

func TestRaw_Wire(t *testing.T) {
	c := NewRaw(200).(*Raw)
	var cps Caps

	err := c.Unmarshal([]byte{0x01}, cps)
	require.NoError(t, err)
	err = c.Unmarshal([]byte{0x02, 0x03}, cps)
	require.NoError(t, err)

	buf := c.Marshal(nil)
	require.Equal(t, []byte{200, 1, 0x01, 200, 2, 0x02, 0x03}, buf)
}

func TestMP_Multiple_Wire(t *testing.T) {
	c := NewMP(CAP_MP).(*MP)
	var cps Caps

	// Add IPv4 unicast
	err := c.Unmarshal([]byte{0x00, 0x01, 0x00, 0x01}, cps)
	require.NoError(t, err)
	// Add IPv6 unicast
	err = c.Unmarshal([]byte{0x00, 0x02, 0x00, 0x01}, cps)
	require.NoError(t, err)

	require.True(t, c.Has(afi.AFI_IPV4, afi.SAFI_UNICAST))
	require.True(t, c.Has(afi.AFI_IPV6, afi.SAFI_UNICAST))

	buf := c.Marshal(nil)
	require.Len(t, buf, 12) // 2 capabilities * 6 bytes each
}

func TestAddPath_Bidir_Wire(t *testing.T) {
	c := NewAddPath(CAP_ADDPATH).(*AddPath)
	var cps Caps

	err := c.Unmarshal([]byte{0x00, 0x01, 0x01, byte(ADDPATH_BIDIR)}, cps)
	require.NoError(t, err)
	require.True(t, c.Has(afi.AS_IPV4_UNICAST, ADDPATH_SEND))
	require.True(t, c.Has(afi.AS_IPV4_UNICAST, ADDPATH_RECEIVE))

	buf := c.Marshal(nil)
	require.Equal(t, []byte{byte(CAP_ADDPATH), 4, 0x00, 0x01, 0x01, byte(ADDPATH_BIDIR)}, buf)
}

func TestMP_InvalidLength_Wire(t *testing.T) {
	c := NewMP(CAP_MP).(*MP)
	var cps Caps

	err := c.Unmarshal([]byte{0x00, 0x01, 0x00}, cps)
	require.ErrorIs(t, err, ErrLength)
}

func TestRole_Wire(t *testing.T) {
	c := NewRole(CAP_ROLE).(*Role)
	var cps Caps

	// Test Customer role
	err := c.Unmarshal([]byte{ROLE_CUSTOMER}, cps)
	require.NoError(t, err)
	require.Equal(t, ROLE_CUSTOMER, c.Role)

	buf := c.Marshal(nil)
	require.Equal(t, []byte{byte(CAP_ROLE), 1, ROLE_CUSTOMER}, buf)

	// Test invalid length
	err = c.Unmarshal([]byte{}, cps)
	require.ErrorIs(t, err, ErrLength)

	err = c.Unmarshal([]byte{0x00, 0x00}, cps)
	require.ErrorIs(t, err, ErrLength)
}

func TestRole_AllValues_Wire(t *testing.T) {
	var cps Caps

	tests := []struct {
		name  string
		value byte
		json  string
	}{
		{"PROVIDER", ROLE_PROVIDER, `"PROVIDER"`},
		{"RS", ROLE_RS, `"RS"`},
		{"RS-CLIENT", ROLE_RS_CLIENT, `"RS-CLIENT"`},
		{"CUSTOMER", ROLE_CUSTOMER, `"CUSTOMER"`},
		{"PEER", ROLE_PEER, `"PEER"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewRole(CAP_ROLE).(*Role)
			err := c.Unmarshal([]byte{tt.value}, cps)
			require.NoError(t, err)
			require.Equal(t, tt.value, c.Role)

			// Test JSON output
			jsonBuf := c.ToJSON(nil)
			require.Equal(t, tt.json, string(jsonBuf))

			// Test JSON input
			c2 := NewRole(CAP_ROLE).(*Role)
			err = c2.FromJSON([]byte(tt.json))
			require.NoError(t, err)
			require.Equal(t, tt.value, c2.Role)
		})
	}
}

func TestRole_UnknownValue_Wire(t *testing.T) {
	c := NewRole(CAP_ROLE).(*Role)
	var cps Caps

	// Unknown role value (e.g., 255)
	err := c.Unmarshal([]byte{255}, cps)
	require.NoError(t, err)
	require.Equal(t, byte(255), c.Role)

	// JSON output for unknown value (plain number)
	jsonBuf := c.ToJSON(nil)
	require.Equal(t, `255`, string(jsonBuf))
}
