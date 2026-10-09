package msg

import (
	"testing"

	"github.com/bgpfix/bgpfix/caps"
	"github.com/stretchr/testify/require"
)

// TestAsPath_LongSegmentRoundTrip checks a long AS_PATH survives wire -> JSON -> wire,
// where JSON merges sequence segments into one with >255 ASNs
func TestAsPath_LongSegmentRoundTrip(t *testing.T) {
	var ap []byte
	for _, n := range []int{200, 100} {
		ap = append(ap, 2, byte(n))
		for i := 0; i < n; i++ {
			ap = append(ap, 0, 0, 0xfd, 0xe9)
		}
	}
	ats := []byte{0x40, 1, 1, 0, 0x50, 2, byte(len(ap) >> 8), byte(len(ap))}
	ats = append(ats, ap...)
	ats = append(ats, 0x40, 3, 4, 192, 0, 2, 1)
	data := []byte{0, 0, byte(len(ats) >> 8), byte(len(ats))}
	data = append(data, ats...)
	data = append(data, 24, 1, 1, 1)
	var cps caps.Caps
	cps.Use(caps.CAP_AS4)
	m := NewMsg()
	m.Type = UPDATE
	m.Data = data
	require.NoError(t, m.Parse(cps))
	js := append([]byte(nil), m.GetJSON()...)
	m2 := NewMsg()
	require.NoError(t, m2.FromJSON(js))
	require.NoError(t, m2.Marshal(cps))
	m3 := NewMsg()
	m3.Type = UPDATE
	m3.Data = m2.Data
	require.NoError(t, m3.Parse(cps))
	require.Equal(t, 300, m3.Update.AsPath().Len())
}
