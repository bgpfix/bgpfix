package msg

import (
	"testing"

	"github.com/bgpfix/bgpfix/caps"
	"github.com/stretchr/testify/require"
)

// asPathUpdate returns an UPDATE for 1.1.1.0/24 with given raw AS_PATH and AS4_PATH values
func asPathUpdate(aspath, as4path []byte) []byte {
	ats := []byte{0x40, 1, 1, 0} // ORIGIN IGP
	ats = append(ats, 0x40, 2, byte(len(aspath)))
	ats = append(ats, aspath...)
	ats = append(ats, 0x40, 3, 4, 192, 0, 2, 1) // NEXT_HOP
	ats = append(ats, 0xc0, 17, byte(len(as4path)))
	ats = append(ats, as4path...)

	data := []byte{0, 0, 0, byte(len(ats))}
	data = append(data, ats...)
	return append(data, 24, 1, 1, 1)
}

func TestAsPath_AS4PathIgnoredOnAS4Session(t *testing.T) {
	m := NewMsg()
	m.Type = UPDATE
	m.Data = asPathUpdate(
		[]byte{2, 2, 0, 0, 0xfd, 0xe9, 0, 0, 0x02, 0x9a}, // [65001 666]
		[]byte{2, 2, 0, 0, 0xfd, 0xe9, 0, 0, 0x34, 0x17}, // [65001 13335]
	)
	var cps caps.Caps
	cps.Use(caps.CAP_AS4)
	require.NoError(t, m.Parse(cps))
	require.Equal(t, uint32(666), m.Update.AsPath().Origin())
}

func TestAsPath_AS4PathMergedOn2ByteSession(t *testing.T) {
	m := NewMsg()
	m.Type = UPDATE
	m.Data = asPathUpdate(
		[]byte{2, 2, 0xfd, 0xe9, 0x5b, 0xa0}, // [65001 23456]
		[]byte{2, 1, 0, 3, 0x0d, 0x40},       // [200000]
	)
	require.NoError(t, m.Parse(caps.Caps{}))
	require.Equal(t, "[65001,200000]", m.Update.AsPath().String())
}
