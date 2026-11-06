package msg

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOpen_ResetRestoresDefaults(t *testing.T) {
	m := NewMsg()
	o := &m.Switch(OPEN).Open
	o.Version, o.ASN, o.HoldTime = 5, 65000, 7
	o.Identifier = netip.MustParseAddr("1.2.3.4")

	o = &m.Switch(OPEN).Open // as on a recycled message
	require.EqualValues(t, OPEN_VERSION, o.Version)
	require.Zero(t, o.ASN)
	require.Zero(t, o.HoldTime)
	require.Equal(t, netip.IPv4Unspecified(), o.Identifier)
}

func TestOpen_MarshalNonIPv4Identifier(t *testing.T) {
	m := NewMsg()
	o := &m.Switch(OPEN).Open
	require.NoError(t, m.Open.FromJSON([]byte(`{"bgp":4,"asn":65000,"id":"2001:db8::1","hold":90}`)))
	require.ErrorIs(t, o.Marshal(), ErrValue)

	o.Identifier = netip.MustParseAddr("10.0.0.1")
	require.NoError(t, o.Marshal())
	require.Len(t, m.Data, OPEN_MINLEN)
}
