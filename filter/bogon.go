package filter

import "net/netip"

// bogonPrefixes are special-purpose blocks (RFC 6890) that must not be in the global table
var bogonPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/3"), // multicast and reserved
	netip.MustParsePrefix("::/8"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001:2::/48"),
	netip.MustParsePrefix("2001:10::/28"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("3ffe::/16"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("fec0::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

// bogonASN returns true iff asn must not be in the global table (RFC 5398, 6996, 7300, 6793)
func bogonASN(asn uint32) bool {
	return asn == 0 || asn == 23456 || (asn >= 64496 && asn <= 131071) || asn >= 4200000000
}

// bogon_asn and bogon_prefix take no operator nor value
func (e *Expr) bogonParse() error {
	if e.Op != OP_PRESENT || e.Idx != nil {
		return ErrOp
	}
	return nil
}

// bogonAsnEval: any bogon ASN in AS_PATH (merged with AS4_PATH)?
func (e *Expr) bogonAsnEval(ev *Eval) Res {
	ap := ev.Msg.Update.AsPath()
	if ap == nil {
		return RES_ABSENT
	}
	for _, seg := range ap.Segments {
		for _, asn := range seg.List {
			if bogonASN(asn) {
				return RES_TRUE
			}
		}
	}
	return RES_FALSE
}

// bogonPrefixEval: any announced prefix within a bogon block?
func (e *Expr) bogonPrefixEval(ev *Eval) Res {
	reach := ev.Msg.Update.AllReach()
	if len(reach) == 0 {
		return RES_ABSENT
	}
	for _, p := range reach {
		for _, b := range bogonPrefixes {
			if b.Bits() <= p.Bits() && b.Contains(p.Addr()) {
				return RES_TRUE
			}
		}
	}
	return RES_FALSE
}
