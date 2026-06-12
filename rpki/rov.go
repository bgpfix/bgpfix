package rpki

import "net/netip"

// ValidateOrigin performs Route Origin Validation (RFC 6811) of prefix p
// announced by the origin ASN, against VRP snapshots v4 and v6 (see
// Cache.VRPs). Returns ROV_VALID, ROV_INVALID, or ROV_NOT_FOUND.
// NB: origin 0 (eg. unknown) never validates.
func ValidateOrigin(v4, v6 VRPs, p netip.Prefix, origin uint32) int {
	var vrps VRPs
	var minLen int
	if p.Addr().Is4() {
		minLen = MIN_VRP_V4
		vrps = v4
	} else {
		minLen = MIN_VRP_V6
		vrps = v6
	}
	if len(vrps) == 0 {
		return ROV_NOT_FOUND
	}

	// find covering VRPs from most- to least-specific
	var found bool
	addr, bits := p.Addr(), uint8(p.Bits())
	for try := p.Bits(); try >= minLen; try-- {
		p, _ := addr.Prefix(try)
		for _, e := range vrps[p] {
			if origin != 0 && origin == e.ASN && bits <= e.MaxLen {
				return ROV_VALID
			}
			found = true
		}
	}

	if found {
		return ROV_INVALID
	}
	return ROV_NOT_FOUND
}

// ValidateOrigin performs ROV against the current cache snapshot.
// See the package-level ValidateOrigin.
func (c *Cache) ValidateOrigin(p netip.Prefix, origin uint32) int {
	v4, v6 := c.VRPs()
	return ValidateOrigin(v4, v6, p, origin)
}
