package rpki

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestVerifyPath_Vectors runs the examples from "ASPA-based AS path verification
// examples" (Sriram, Borchert, Matejka; Oct 2026), referenced by Sec. 6.1 of
// draft-ietf-sidrops-aspa-verification-29: github.com/ksriram25/IETF
func TestVerifyPath_Vectors(t *testing.T) {
	// ASes are letters A..S -> 1..19; an AS0 ASPA is an empty provider set
	as := func(c byte) uint32 { return uint32(c-'A') + 1 }
	aspas := func(m map[byte]string) ASPA {
		a := make(ASPA)
		for cas, provs := range m {
			a[as(cas)] = []uint32{}
			for i := range len(provs) {
				a[as(cas)] = append(a[as(cas)], as(provs[i]))
			}
		}
		return a
	}
	path := func(s string) (p []uint32) {
		for i := range len(s) {
			p = append(p, as(s[i]))
		}
		return
	}

	// Tables 1 and 2: A{C,D} B{E} C{F} D{F,G} G{AS0}; E, F: no ASPA
	t12 := aspas(map[byte]string{'A': "CD", 'B': "E", 'C': "F", 'D': "FG", 'G': ""})
	// Table 3: H{AS0} K{AS0} L{K} P{AS0} Q{AS0} R{Q} S{R}; J: no ASPA
	t3 := aspas(map[byte]string{'H': "", 'K': "", 'L': "K", 'P': "", 'Q': "", 'R': "Q", 'S': "R"})

	V, U, I := ASPA_VALID, ASPA_UNKNOWN, ASPA_INVALID
	tests := []struct {
		name string
		aspa ASPA
		path string // received AS_PATH (unique ASes), neighbor first
		down bool   // downstream (from a provider)?
		want int
	}{
		// Table 1: upstream (from a customer or lateral peer)
		{"T1#1", t12, "FCA", false, V},
		{"T1#2", t12, "DCA", false, I},
		{"T1#3", t12, "DFCA", false, U},
		{"T1#4", t12, "DEB", false, U},
		{"T1#5", t12, "ADEB", false, I},
		{"T1#6", t12, "ADGEB", false, I},
		{"T1#7", t12, "ACF", false, I},
		{"T1#8", t12, "ACFG", false, I},
		{"T1#9", t12, "EB", false, V},

		// Table 2: downstream (from a provider)
		{"T2#1", t12, "EGFCA", true, U},
		{"T2#2", t12, "EGDA", true, V},
		{"T2#3", t12, "EDCA", true, U},
		{"T2#4", t12, "EGDCA", true, I},
		{"T2#5", t12, "CFDG", true, U},
		{"T2#6", t12, "DGEB", true, V},
		{"T2#7", t12, "CDGEB", true, I},
		{"T2#8", t12, "FCA", true, V},
		{"T2#9", t12, "EA", true, V},   // forged origin by a provider: undetectable
		{"T2#10", t12, "ECA", true, V}, // forged path segment by a provider: undetectable

		// Table 3: complex BGP relationships
		{"T3#1", t3, "JH", false, I},
		{"T3#2", t3, "JH", false, I},
		{"T3#3", t3, "KJH", true, I},
		{"T3#4", t3, "QP", false, I},
		{"T3#5", t3, "QP", true, V},
		{"T3#6", t3, "RQP", true, V},
	}
	for _, tc := range tests {
		got, _, _ := VerifyPath(tc.aspa, path(tc.path), tc.down)
		require.Equal(t, tc.want, got, "%s: %s", tc.name, tc.path)
	}
}
