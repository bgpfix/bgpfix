package rpki

import (
	"net/netip"
	"testing"
)

func TestValidateOriginExactMatch(t *testing.T) {
	// VRP: 192.0.2.0/24-24 AS65001
	v4 := VRPs{
		netip.MustParsePrefix("192.0.2.0/24"): {
			{MaxLen: 24, ASN: 65001},
		},
	}

	tests := []struct {
		name   string
		prefix string
		origin uint32
		want   int
	}{
		{"exact match valid", "192.0.2.0/24", 65001, ROV_VALID},
		{"exact match wrong ASN", "192.0.2.0/24", 65002, ROV_INVALID},
		{"no VRP", "203.0.113.0/24", 65001, ROV_NOT_FOUND},
		{"zero origin", "192.0.2.0/24", 0, ROV_INVALID},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := netip.MustParsePrefix(tt.prefix)
			got := ValidateOrigin(v4, nil, p, tt.origin)
			if got != tt.want {
				t.Errorf("got %d, want %d", got, tt.want)
			}
		})
	}
}

func TestValidateOriginUnmaskedInput(t *testing.T) {
	// VRP stored masked, as Cache.AddVRP would store it
	v4 := VRPs{
		netip.MustParsePrefix("192.0.2.0/24"): {
			{MaxLen: 24, ASN: 65001},
		},
	}

	// input with host bits set must still resolve to the masked key
	p := netip.MustParsePrefix("192.0.2.123/24")
	if got := ValidateOrigin(v4, nil, p, 65001); got != ROV_VALID {
		t.Errorf("unmasked input: got %d, want ROV_VALID", got)
	}
}

func TestValidateOriginMaxLen(t *testing.T) {
	// VRP: 192.0.2.0/24-26 AS65001 (allows up to /26)
	v4 := VRPs{
		netip.MustParsePrefix("192.0.2.0/24"): {
			{MaxLen: 26, ASN: 65001},
		},
	}

	tests := []struct {
		name   string
		prefix string
		origin uint32
		want   int
	}{
		{"within maxLen /24", "192.0.2.0/24", 65001, ROV_VALID},
		{"within maxLen /25", "192.0.2.0/25", 65001, ROV_VALID},
		{"within maxLen /26", "192.0.2.0/26", 65001, ROV_VALID},
		{"exceeds maxLen /27", "192.0.2.0/27", 65001, ROV_INVALID},
		{"exceeds maxLen /28", "192.0.2.0/28", 65001, ROV_INVALID},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := netip.MustParsePrefix(tt.prefix)
			got := ValidateOrigin(v4, nil, p, tt.origin)
			if got != tt.want {
				t.Errorf("got %d, want %d", got, tt.want)
			}
		})
	}
}

func TestValidateOriginCoveringVRP(t *testing.T) {
	// VRP: 192.0.2.0/22-24 AS65001 (covers /22, /23, /24)
	v4 := VRPs{
		netip.MustParsePrefix("192.0.2.0/22").Masked(): {
			{MaxLen: 24, ASN: 65001},
		},
	}

	tests := []struct {
		name   string
		prefix string
		origin uint32
		want   int
	}{
		{"covered /22 valid", "192.0.2.0/22", 65001, ROV_VALID},
		{"covered /23 valid", "192.0.2.0/23", 65001, ROV_VALID},
		{"covered /24 valid", "192.0.2.0/24", 65001, ROV_VALID},
		{"covered /24 different subnet valid", "192.0.3.0/24", 65001, ROV_VALID},
		{"exceeds maxLen /25", "192.0.2.0/25", 65001, ROV_INVALID},
		{"covered wrong ASN", "192.0.2.0/23", 65002, ROV_INVALID},
		{"outside range", "192.0.6.0/24", 65001, ROV_NOT_FOUND},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := netip.MustParsePrefix(tt.prefix)
			got := ValidateOrigin(v4, nil, p, tt.origin)
			if got != tt.want {
				t.Errorf("got %d, want %d", got, tt.want)
			}
		})
	}
}

func TestValidateOriginIPv6(t *testing.T) {
	// VRP: 2001:db8::/32-48 AS65001
	v6 := VRPs{
		netip.MustParsePrefix("2001:db8::/32"): {
			{MaxLen: 48, ASN: 65001},
		},
	}

	tests := []struct {
		name   string
		prefix string
		origin uint32
		want   int
	}{
		{"exact match", "2001:db8::/32", 65001, ROV_VALID},
		{"covered /48", "2001:db8:1234::/48", 65001, ROV_VALID},
		{"exceeds maxLen /64", "2001:db8:1234:5678::/64", 65001, ROV_INVALID},
		{"wrong ASN", "2001:db8::/32", 65002, ROV_INVALID},
		{"different prefix", "2001:db9::/32", 65001, ROV_NOT_FOUND},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := netip.MustParsePrefix(tt.prefix)
			got := ValidateOrigin(nil, v6, p, tt.origin)
			if got != tt.want {
				t.Errorf("got %d, want %d", got, tt.want)
			}
		})
	}
}

func TestValidateOriginMultipleVRPs(t *testing.T) {
	// multiple VRPs for same prefix (MOAS scenario)
	v4 := VRPs{
		netip.MustParsePrefix("192.0.2.0/24"): {
			{MaxLen: 24, ASN: 65001},
			{MaxLen: 26, ASN: 65002},
			{MaxLen: 24, ASN: 65003},
		},
	}

	tests := []struct {
		name   string
		prefix string
		origin uint32
		want   int
	}{
		{"match AS65001", "192.0.2.0/24", 65001, ROV_VALID},
		{"match AS65002 /24", "192.0.2.0/24", 65002, ROV_VALID},
		{"match AS65002 /26", "192.0.2.0/26", 65002, ROV_VALID},
		{"AS65001 exceeds maxLen", "192.0.2.0/25", 65001, ROV_INVALID},
		{"AS65003 /24", "192.0.2.0/24", 65003, ROV_VALID},
		{"no matching ASN", "192.0.2.0/24", 65999, ROV_INVALID},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := netip.MustParsePrefix(tt.prefix)
			got := ValidateOrigin(v4, nil, p, tt.origin)
			if got != tt.want {
				t.Errorf("got %d, want %d", got, tt.want)
			}
		})
	}
}

func TestValidateOriginMinVRPLen(t *testing.T) {
	// VRP for /7 (too short, below MIN_VRP_V4)
	v4 := VRPs{
		netip.MustParsePrefix("128.0.0.0/7"): {
			{MaxLen: 24, ASN: 65001},
		},
	}

	// /24 within /7 range - should NOT match (stops at /8)
	p := netip.MustParsePrefix("128.1.0.0/24")
	got := ValidateOrigin(v4, nil, p, 65001)

	if got != ROV_NOT_FOUND {
		t.Errorf("should not check beyond MIN_VRP_V4, got %d", got)
	}
}

func TestValidateOriginEmptyCache(t *testing.T) {
	tests := []struct {
		name string
		v4   VRPs
		v6   VRPs
	}{
		{"nil cache", nil, nil},
		{"empty map v4", VRPs{}, nil},
		{"empty map v6", nil, VRPs{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p4 := netip.MustParsePrefix("192.0.2.0/24")
			p6 := netip.MustParsePrefix("2001:db8::/32")

			got4 := ValidateOrigin(tt.v4, nil, p4, 65001)
			got6 := ValidateOrigin(nil, tt.v6, p6, 65001)

			if got4 != ROV_NOT_FOUND || got6 != ROV_NOT_FOUND {
				t.Errorf("empty cache should return ROV_NOT_FOUND")
			}
		})
	}
}

func TestCacheValidateOrigin(t *testing.T) {
	c := NewCache(nil)
	c.AddVRP(true, netip.MustParsePrefix("192.0.2.0/24"), 24, 65001)

	p := netip.MustParsePrefix("192.0.2.0/24")

	// before Apply: pending data is not visible
	if got := c.ValidateOrigin(p, 65001); got != ROV_NOT_FOUND {
		t.Errorf("before Apply: got %d, want ROV_NOT_FOUND", got)
	}

	c.Apply()
	if got := c.ValidateOrigin(p, 65001); got != ROV_VALID {
		t.Errorf("after Apply: got %d, want ROV_VALID", got)
	}
	if got := c.ValidateOrigin(p, 65002); got != ROV_INVALID {
		t.Errorf("wrong origin: got %d, want ROV_INVALID", got)
	}
}
