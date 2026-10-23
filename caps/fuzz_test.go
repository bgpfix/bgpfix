package caps

import (
	"bytes"
	"testing"
)

var fuzzCodes = []Code{CAP_MP, CAP_EXTENDED_NEXTHOP, CAP_ROLE, CAP_AS4, CAP_ADDPATH, CAP_FQDN, CAP_ROUTE_REFRESH, CAP_GRACEFUL_RESTART}

// FuzzCapWire feeds arbitrary bytes to every Cap.Unmarshal, then checks that
// whatever parsed can be marshaled, dumped to JSON and loaded back.
func FuzzCapWire(f *testing.F) {
	f.Add([]byte{0, 1, 0, 1})
	f.Add([]byte{0, 1, 1, 3})
	f.Add([]byte{0, 1, 0, 1, 0, 2})
	f.Add([]byte{4, 'b', 'g', 'p', 'd', 3, 'n', 'e', 't'})
	f.Add([]byte{2, 'a', 'b'})
	f.Add([]byte{0, 0, 0xfd, 0xe9})
	f.Add([]byte{3})
	f.Fuzz(func(t *testing.T, data []byte) {
		var cps Caps
		for _, cc := range fuzzCodes {
			c := NewCap(cc)
			// multiple calls must be supported
			e1 := c.Unmarshal(data, cps)
			e2 := c.Unmarshal(data, cps)
			if e1 != nil || e2 != nil {
				continue
			}
			wire := c.Marshal(nil)
			js := c.ToJSON(nil)

			// NB: unassigned AFI/SAFI print as "SAFI(n)", which FromJSON rejects (known)
			if bytes.Contains(js, []byte("AFI(")) {
				continue
			}

			c2 := NewCap(cc)
			if err := c2.FromJSON(js); err != nil {
				t.Fatalf("%s: FromJSON(ToJSON()) failed: %v: %s", cc, err, js)
			}
			// NB: Fqdn.FromJSON does not unescape strings (known, cosmetic)
			if wire2 := c2.Marshal(nil); cc != CAP_FQDN && !bytes.Equal(wire, wire2) {
				t.Fatalf("%s: JSON roundtrip changed wire: %x -> %x (%s)", cc, wire, wire2, js)
			}
			c.Intersect(c2)
			c2.Intersect(c)
		}
	})
}

// FuzzCapsJSON feeds arbitrary JSON to Caps.FromJSON.
func FuzzCapsJSON(f *testing.F) {
	f.Add([]byte(`{"MP":["IPV4/UNICAST"],"AS4":65000,"ROLE":"PEER","ADDPATH":["IPV4/UNICAST/SEND"],"FQDN":{"host":"a","domain":"b"},"EXTENDED_NEXTHOP":["IPV4/UNICAST/IPV6"],"CAP_200":"0102"}`))
	f.Add([]byte(`{"CAP_9":true,"CAP_10":["01",""]}`))
	f.Add([]byte(`{"CAP_9":}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var cps Caps
		cps.Init()
		if err := cps.FromJSON(data); err != nil {
			return
		}
		js := cps.ToJSON(nil)
		var c2 Caps
		c2.Init()
		if err := c2.FromJSON(js); err != nil {
			t.Fatalf("roundtrip: %v: %s", err, js)
		}
		cps.Each(func(i int, cc Code, c Cap) { c.Marshal(nil) })
	})
}
