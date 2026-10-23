package afi

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAS_JSON_Unassigned(t *testing.T) {
	for _, as := range []AS{
		NewAS(AFI_IPV4, SAFI_UNICAST),
		NewAS(AFI(12336), SAFI(48)), // not in the enums
		NewAS(AFI_IPV6, SAFI(3)),
	} {
		var got AS
		require.NoError(t, got.FromJSON(as.ToJSON(nil)), as.ToJSON(nil))
		require.Equal(t, as, got)

		asv := NewASV(as.Afi(), as.Safi(), 1)
		var got2 ASV
		require.NoError(t, got2.FromJSON(asv.ToJSON(nil, ""), nil), asv.ToJSON(nil, ""))
		require.Equal(t, asv, got2)
	}

	_, err := ParseAFI("AFI(70000)")
	require.Error(t, err)
	_, err = ParseSAFI("SAFI(256)")
	require.Error(t, err)
	_, err = ParseSAFI("SAFI(x)")
	require.Error(t, err)
}
