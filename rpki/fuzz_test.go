package rpki

import (
	"net/netip"
	"testing"
)

// FuzzRpkiParse feeds arbitrary data to Cache.Parse, then uses the result.
func FuzzRpkiParse(f *testing.F) {
	f.Add([]byte(`{"roas":[{"prefix":"192.0.2.0/24","maxLength":24,"asn":"AS65000"}],"aspas":[{"customer_asid":65000,"providers":[65001,65002]}]}`))
	f.Add([]byte("ASN,IP Prefix,Max Length\nAS65000,192.0.2.0/24,24\nAS65000,2001:db8::/32,48\n"))
	f.Add([]byte("<html>502</html>"))
	f.Fuzz(func(t *testing.T, data []byte) {
		c := NewCache(nil)
		if c.Parse(data) != nil {
			return
		}
		c.Apply()
		for _, p := range []string{"192.0.2.0/24", "2001:db8::/32", "10.0.0.0/8", "::/0"} {
			c.ValidateOrigin(netip.MustParsePrefix(p), 65000)
		}
		path := []uint32{65001, 65000, 65002}
		c.VerifyPath(path, false)
		c.VerifyPath(path, true)
	})
}
