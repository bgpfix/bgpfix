package rpki

import (
	"encoding/binary"
	"net/netip"
)

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

// rovMemoBits sets the size of the ROV verdict memo: small enough to stay in the CPU cache
const rovMemoBits = 10

// rovMemo is a verdict remembered by Cache.ValidateOrigin
type rovMemo struct {
	gen    uint64
	p      netip.Prefix
	origin uint32
	res    int
}

// rovSlot picks the memo slot for the question
func rovSlot(p netip.Prefix, origin uint32) uint64 {
	a := p.Addr().As16()
	lo := binary.BigEndian.Uint64(a[8:])
	hi := binary.BigEndian.Uint64(a[:8])
	h := hi*0x9e3779b97f4a7c15 ^ lo*0xc2b2ae3d27d4eb4f ^ (uint64(p.Bits())<<32|uint64(origin))*0x165667b19e3779f9
	return (h ^ h>>29) >> (64 - rovMemoBits)
}

// ValidateOrigin performs ROV against the current cache snapshot.
// See the package-level ValidateOrigin.
//
// Verdicts are memoized in a small lock-free table: RIB dumps list the same
// prefix once per peer, and update feeds repeat announcements, so most
// questions were asked recently. The cache snapshot generation tells when
// an entry went stale.
func (c *Cache) ValidateOrigin(p netip.Prefix, origin uint32) int {
	// NB: load gen before the snapshots. Apply publishes them first and bumps gen after,
	// so a memo labeled with gen is from that snapshot or a newer one; a stale label only costs a miss
	gen := c.gen.Load()
	slot := &c.rovMemo[rovSlot(p, origin)]
	if m := slot.Load(); m != nil && m.gen == gen && m.origin == origin && m.p == p {
		return m.res
	}

	v4, v6 := c.VRPs()
	res := ValidateOrigin(v4, v6, p, origin)
	slot.Store(&rovMemo{gen, p, origin, res})
	return res
}
