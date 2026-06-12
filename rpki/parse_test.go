package rpki

import (
	"net/netip"
	"testing"
)

func TestParseJSON_ValidRoutinatorFormat(t *testing.T) {
	c := NewCache(nil)

	json := []byte(`{
		"roas": [
			{"prefix": "192.0.2.0/24", "maxLength": 24, "asn": "AS65001"},
			{"prefix": "203.0.113.0/24", "maxLength": 26, "asn": 65002},
			{"prefix": "2001:db8::/32", "maxLength": 48, "asn": 65003}
		]
	}`)

	if err := c.ParseJSON(json); err != nil {
		t.Fatalf("parse error: %v", err)
	}

	if len(c.next4) != 2 {
		t.Errorf("expected 2 IPv4 VRPs, got %d", len(c.next4))
	}

	p1 := netip.MustParsePrefix("192.0.2.0/24")
	if entries := c.next4[p1]; len(entries) != 1 {
		t.Errorf("expected 1 entry for 192.0.2.0/24, got %d", len(entries))
	} else if entries[0].ASN != 65001 || entries[0].MaxLen != 24 {
		t.Errorf("wrong entry: %+v", entries[0])
	}

	p2 := netip.MustParsePrefix("203.0.113.0/24")
	if entries := c.next4[p2]; len(entries) != 1 {
		t.Errorf("expected 1 entry for 203.0.113.0/24, got %d", len(entries))
	} else if entries[0].ASN != 65002 || entries[0].MaxLen != 26 {
		t.Errorf("wrong entry: %+v", entries[0])
	}

	if len(c.next6) != 1 {
		t.Errorf("expected 1 IPv6 VRP, got %d", len(c.next6))
	}

	p3 := netip.MustParsePrefix("2001:db8::/32")
	if entries := c.next6[p3]; len(entries) != 1 {
		t.Errorf("expected 1 entry for 2001:db8::/32, got %d", len(entries))
	} else if entries[0].ASN != 65003 || entries[0].MaxLen != 48 {
		t.Errorf("wrong entry: %+v", entries[0])
	}
}

func TestParseJSON_ASNFormats(t *testing.T) {
	tests := []struct {
		name   string
		json   string
		wantOK bool
		asn    uint32
	}{
		{"string AS prefix", `{"roas": [{"prefix": "192.0.2.0/24", "maxLength": 24, "asn": "AS65001"}]}`, true, 65001},
		{"string no prefix", `{"roas": [{"prefix": "192.0.2.0/24", "maxLength": 24, "asn": "65001"}]}`, true, 65001},
		{"integer", `{"roas": [{"prefix": "192.0.2.0/24", "maxLength": 24, "asn": 65001}]}`, true, 65001},
		{"float", `{"roas": [{"prefix": "192.0.2.0/24", "maxLength": 24, "asn": 65001.0}]}`, true, 65001},
		{"uppercase AS", `{"roas": [{"prefix": "192.0.2.0/24", "maxLength": 24, "asn": "AS65001"}]}`, true, 65001},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewCache(nil)

			err := c.ParseJSON([]byte(tt.json))
			if tt.wantOK && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !tt.wantOK && err == nil {
				t.Fatal("expected error, got nil")
			}

			if tt.wantOK {
				p := netip.MustParsePrefix("192.0.2.0/24")
				if entries := c.next4[p]; len(entries) != 1 {
					t.Fatalf("expected 1 entry, got %d", len(entries))
				} else if entries[0].ASN != tt.asn {
					t.Errorf("got ASN %d, want %d", entries[0].ASN, tt.asn)
				}
			}
		})
	}
}

func TestParseJSON_InvalidInputs(t *testing.T) {
	tests := []struct {
		name string
		json string
	}{
		{"invalid JSON", `{invalid json}`},
		{"missing roas field", `{}`},
		{"invalid prefix", `{"roas": [{"prefix": "not-a-prefix", "maxLength": 24, "asn": 65001}]}`},
		{"maxLength too small", `{"roas": [{"prefix": "192.0.2.0/24", "maxLength": 23, "asn": 65001}]}`},
		{"maxLength too large", `{"roas": [{"prefix": "192.0.2.0/24", "maxLength": 129, "asn": 65001}]}`},
		{"invalid ASN string", `{"roas": [{"prefix": "192.0.2.0/24", "maxLength": 24, "asn": "invalid"}]}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewCache(nil)

			// should either error or skip the invalid entry
			c.ParseJSON([]byte(tt.json))

			if len(c.next4)+len(c.next6) != 0 {
				t.Errorf("invalid input produced VRPs: v4=%d v6=%d", len(c.next4), len(c.next6))
			}
		})
	}
}

func TestParseJSON_ASPA_BothKeyVariants(t *testing.T) {
	// Routinator uses `provider_asids`, rpki-client uses `providers`
	// and encodes "no providers" as [0] — AddASPA must strip zeros.
	json := []byte(`{
		"roas": [],
		"aspas": [
			{"customer_asid": 65001, "provider_asids": [65010, 65011]},
			{"customer_asid": 65002, "providers": [65020, 65021]},
			{"customer_asid": 65003, "providers": [0]}
		]
	}`)

	c := NewCache(nil)
	if err := c.ParseJSON(json); err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if got := c.nextAspa[65001]; len(got) != 2 || got[0] != 65010 || got[1] != 65011 {
		t.Errorf("Routinator key: got %v, want [65010 65011]", got)
	}
	if got := c.nextAspa[65002]; len(got) != 2 || got[0] != 65020 || got[1] != 65021 {
		t.Errorf("rpki-client key: got %v, want [65020 65021]", got)
	}
	if got, ok := c.nextAspa[65003]; !ok || len(got) != 0 {
		t.Errorf(`rpki-client "no providers" ([0]): got %v (ok=%v), want empty slice`, got, ok)
	}
}

func TestParseCSV_Valid(t *testing.T) {
	c := NewCache(nil)

	csv := []byte(`prefix,maxLength,asn
192.0.2.0/24,24,AS65001
203.0.113.0/24,26,65002
2001:db8::/32,48,AS65003
`)

	if err := c.ParseCSV(csv); err != nil {
		t.Fatalf("parse error: %v", err)
	}

	if len(c.next4) != 2 {
		t.Errorf("expected 2 IPv4 VRPs, got %d", len(c.next4))
	}
	if len(c.next6) != 1 {
		t.Errorf("expected 1 IPv6 VRP, got %d", len(c.next6))
	}

	p1 := netip.MustParsePrefix("192.0.2.0/24")
	if entries := c.next4[p1]; len(entries) != 1 || entries[0].ASN != 65001 {
		t.Errorf("wrong entry for 192.0.2.0/24: %+v", entries)
	}
}

func TestParseCSV_NoHeader(t *testing.T) {
	c := NewCache(nil)

	csv := []byte(`192.0.2.0/24,24,65001
203.0.113.0/24,26,65002`)

	if err := c.ParseCSV(csv); err != nil {
		t.Fatalf("parse error: %v", err)
	}

	if len(c.next4) != 2 {
		t.Errorf("expected 2 IPv4 VRPs, got %d", len(c.next4))
	}
}

func TestParseCSV_Comments(t *testing.T) {
	c := NewCache(nil)

	csv := []byte(`# This is a comment
192.0.2.0/24,24,65001
# Another comment
203.0.113.0/24,26,65002

# Empty lines above and below
`)

	if err := c.ParseCSV(csv); err != nil {
		t.Fatalf("parse error: %v", err)
	}

	if len(c.next4) != 2 {
		t.Errorf("expected 2 IPv4 VRPs (comments ignored), got %d", len(c.next4))
	}
}

func TestParseCSV_Whitespace(t *testing.T) {
	c := NewCache(nil)

	csv := []byte(`  192.0.2.0/24  ,  24  ,  AS65001
203.0.113.0/24,26,65002`)

	if err := c.ParseCSV(csv); err != nil {
		t.Fatalf("parse error: %v", err)
	}

	p := netip.MustParsePrefix("192.0.2.0/24")
	if entries := c.next4[p]; len(entries) != 1 || entries[0].ASN != 65001 {
		t.Errorf("whitespace not trimmed properly: %+v", entries)
	}
}

func TestParseCSV_InvalidLines(t *testing.T) {
	c := NewCache(nil)

	csv := []byte(`192.0.2.0/24,24,65001
invalid line
203.0.113.0/24,invalid,65002
204.0.113.0/24,24,invalid-asn
205.0.113.0/24,23,65003
206.0.113.0/24,25,65004`)

	if err := c.ParseCSV(csv); err != nil {
		t.Fatalf("parse error: %v", err)
	}

	// should have 2 valid entries (first and last)
	if len(c.next4) != 2 {
		t.Errorf("expected 2 valid IPv4 VRPs, got %d", len(c.next4))
	}
}

func TestParse_AutoDetect(t *testing.T) {
	tests := []struct {
		name   string
		data   []byte
		wantV4 int
		wantV6 int
	}{
		{
			name:   "JSON detected",
			data:   []byte(`{"roas": [{"prefix": "192.0.2.0/24", "maxLength": 24, "asn": 65001}]}`),
			wantV4: 1,
		},
		{
			name:   "CSV detected",
			data:   []byte("192.0.2.0/24,24,65001"),
			wantV4: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewCache(nil)

			if err := c.Parse(tt.data); err != nil {
				t.Fatalf("parse error: %v", err)
			}

			if len(c.next4) != tt.wantV4 {
				t.Errorf("got %d IPv4 VRPs, want %d", len(c.next4), tt.wantV4)
			}
			if len(c.next6) != tt.wantV6 {
				t.Errorf("got %d IPv6 VRPs, want %d", len(c.next6), tt.wantV6)
			}
		})
	}
}

func TestParse_Empty(t *testing.T) {
	c := NewCache(nil)
	if err := c.Parse([]byte("  \n ")); err == nil {
		t.Error("expected error on empty data")
	}
}

func TestParse_PrefixMasking(t *testing.T) {
	c := NewCache(nil)

	// unmasked prefix in JSON
	json := []byte(`{"roas": [{"prefix": "192.0.2.123/24", "maxLength": 24, "asn": 65001}]}`)
	if err := c.ParseJSON(json); err != nil {
		t.Fatalf("parse error: %v", err)
	}

	// should be stored as masked 192.0.2.0/24
	masked := netip.MustParsePrefix("192.0.2.0/24")
	if _, exists := c.next4[masked]; !exists {
		t.Error("prefix not properly masked in JSON parse")
	}
}
