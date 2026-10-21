package attrs

import "testing"

// a typical UPDATE: a handful of attributes, set, queried, iterated, reset
func BenchmarkAttrs(b *testing.B) {
	codes := []Code{ATTR_ORIGIN, ATTR_ASPATH, ATTR_NEXTHOP, ATTR_MED, ATTR_COMMUNITY, ATTR_LARGE_COMMUNITY}
	var ats Attrs
	b.ReportAllocs()
	for b.Loop() {
		for _, c := range codes {
			ats.Use(c)
		}
		for _, c := range codes {
			if !ats.Has(c) || ats.Get(c) == nil {
				b.Fatal("missing")
			}
		}
		_ = ats.Has(ATTR_LOCALPREF)
		n := 0
		ats.Each(func(i int, ac Code, at Attr) { n++ })
		ats.Reset()
	}
}
