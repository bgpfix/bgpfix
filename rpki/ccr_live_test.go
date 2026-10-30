//go:build live

package rpki

import (
	"os"
	"slices"
	"testing"
	"time"
)

// TestLive_CCR reads a real rpki-client CCR and compares it with the JSON export of the same run.
//
// Run with: CCR_FILE=x.ccr CCR_JSON=x.json go test -tags live -run TestLive_CCR -v ./rpki/
func TestLive_CCR(t *testing.T) {
	cf, jf := os.Getenv("CCR_FILE"), os.Getenv("CCR_JSON")
	if cf == "" || jf == "" {
		t.Skip("set CCR_FILE and CCR_JSON")
	}
	ccr, err := os.ReadFile(cf)
	if err != nil {
		t.Fatal(err)
	}
	js, err := os.ReadFile(jf)
	if err != nil {
		t.Fatal(err)
	}

	a, b := NewCache(nil), NewCache(nil)
	t0 := time.Now()
	if err := a.Parse(ccr); err != nil {
		t.Fatal(err)
	}
	t.Logf("parsed CCR in %v", time.Since(t0))
	if err := b.Parse(js); err != nil {
		t.Fatal(err)
	}
	a.Apply()
	b.Apply()

	info, err := ReadCCR(ccr, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("CCR: produced %s, %d VRPs, %d ASPAs", info.ProducedAt, info.VRPs, info.VAPs)

	// same VRPs and ASPAs as rpki-client's own JSON of the same run
	for i, pair := range [][2]VRPs{{first(a.VRPs()), first(b.VRPs())}, {second(a.VRPs()), second(b.VRPs())}} {
		if len(pair[0]) != len(pair[1]) {
			t.Fatalf("family %d: %d prefixes in CCR, %d in JSON", i, len(pair[0]), len(pair[1]))
		}
		for p, ea := range pair[0] {
			eb := slices.Clone(pair[1][p])
			ea = slices.Clone(ea)
			cmp := func(x, y VRP) int { return int(x.ASN)<<8 | int(x.MaxLen) - (int(y.ASN)<<8 | int(y.MaxLen)) }
			slices.SortFunc(ea, cmp)
			slices.SortFunc(eb, cmp)
			if !slices.Equal(ea, eb) {
				t.Fatalf("%s: CCR %v, JSON %v", p, ea, eb)
			}
		}
	}
	aa, ab := a.ASPAs(), b.ASPAs()
	if len(aa) != len(ab) {
		t.Fatalf("%d ASPAs in CCR, %d in JSON", len(aa), len(ab))
	}
	for cas, pa := range aa {
		if !slices.Equal(pa, ab[cas]) {
			t.Fatalf("AS%d: CCR %v, JSON %v", cas, pa, ab[cas])
		}
	}
	v4, v6, as := a.Sizes()
	t.Logf("identical: %d v4 prefixes, %d v6 prefixes, %d ASPAs", v4, v6, as)
}

func first(a, _ VRPs) VRPs  { return a }
func second(_, b VRPs) VRPs { return b }
