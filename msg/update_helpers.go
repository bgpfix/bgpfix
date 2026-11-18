package msg

import (
	"net/netip"
	"slices"

	"github.com/bgpfix/bgpfix/afi"
	"github.com/bgpfix/bgpfix/attrs"
	"github.com/bgpfix/bgpfix/caps"
	"github.com/bgpfix/bgpfix/nlri"
)

// ReachMP returns raw MP-BGP attribute ATTR_MP_REACH, or nil
func (u *Update) ReachMP() *attrs.MP {
	if u == nil || u.Msg.Upper != UPDATE {
		return nil
	}
	a, _ := u.Attrs.Get(attrs.ATTR_MP_REACH).(*attrs.MP)
	return a
}

// UnreachMP returns raw MP-BGP attribute ATTR_MP_UNREACH, or nil
func (u *Update) UnreachMP() *attrs.MP {
	if u == nil || u.Msg.Upper != UPDATE {
		return nil
	}
	a, _ := u.Attrs.Get(attrs.ATTR_MP_UNREACH).(*attrs.MP)
	return a
}

// AfiSafi returns the message AFI+SAFI, giving priority to MP-BGP attributes
func (u *Update) AfiSafi() afi.AS {
	if !u.recache() {
		return 0
	}

	as, ok := u.cache["afisafi"].(afi.AS)
	if ok {
		return as
	}

	if reach := u.ReachMP(); reach != nil {
		as = reach.AS
	} else if unreach := u.UnreachMP(); unreach != nil {
		as = unreach.AS
	} else {
		as = afi.AS_IPV4_UNICAST
	}

	u.cache["afisafi"] = as
	return as
}

// AllReach returns all reachable prefixes, including those in MP-BGP attributes.
// Uses cached value if available. Do not modify the returned slice.
func (u *Update) AllReach() []nlri.Prefix {
	if !u.recache() {
		return nil
	}

	all, ok := u.cache["allreach"].([]nlri.Prefix)
	if ok {
		return all
	}

	// can optimize?
	mp := u.ReachMP().Prefixes()
	if mp == nil {
		all = u.Reach
	} else if len(u.Reach) == 0 {
		all = mp.Prefixes
	} else {
		all = make([]nlri.Prefix, 0, len(u.Reach)+len(mp.Prefixes))
		all = append(all, u.Reach...)
		all = append(all, mp.Prefixes...)
	}

	u.cache["allreach"] = all
	return all
}

// HasReach returns true iff u announces reachable NLRI (for any address family).
func (u *Update) HasReach() bool {
	return len(u.AllReach()) > 0
}

// AddReach adds all reachable prefixes to u.
// NB: it will purge non-IPv6 MP_REACH attribute if needed
func (u *Update) AddReach(prefixes ...nlri.Prefix) {
	if len(prefixes) == 0 {
		return
	} else {
		delete(u.cache, "allreach")
	}

	var mp *attrs.MPPrefixes
	prepare_mp := func() {
		mpr := u.Attrs.Use(attrs.ATTR_MP_REACH).(*attrs.MP)
		mp, _ = mpr.Value.(*attrs.MPPrefixes)
		if mp == nil || mpr.AS != afi.AS_IPV6_UNICAST {
			mp = attrs.NewMPPrefixes(mpr).(*attrs.MPPrefixes)
			mpr.AS = afi.AS_IPV6_UNICAST
			mpr.Value = mp
		}
	}

	for i := range prefixes {
		pfx := &prefixes[i]
		if pfx.Addr().Is4() {
			u.Reach = append(u.Reach, *pfx)
		} else if pfx.Addr().Is6() {
			if mp == nil {
				prepare_mp()
			}
			mp.Prefixes = append(mp.Prefixes, *pfx)
		} // else ignore
	}
}

// AllUnreach returns all unreachable prefixes, including those in MP-BGP attributes.
// Uses cached value if available. Do not modify the returned slice.
func (u *Update) AllUnreach() []nlri.Prefix {
	if !u.recache() {
		return nil
	}

	all, ok := u.cache["allunreach"].([]nlri.Prefix)
	if ok {
		return all
	}

	// can optimize?
	mp := u.UnreachMP().Prefixes()
	if mp == nil {
		all = u.Unreach
	} else if len(u.Unreach) == 0 {
		all = mp.Prefixes
	} else {
		all = make([]nlri.Prefix, 0, len(u.Unreach)+len(mp.Prefixes))
		all = append(all, u.Unreach...)
		all = append(all, mp.Prefixes...)
	}

	u.cache["allunreach"] = all
	return all
}

// HasUnreach returns true iff u withdraws unreachable NLRI (for any address family).
func (u *Update) HasUnreach() bool {
	return len(u.AllUnreach()) > 0
}

// Withdraw turns u into a withdrawal of all its prefixes (RFC 7606 "treat-as-withdraw"):
// announced prefixes are moved to withdrawn, and other attributes are dropped
// (RFC 4271 section 4.3). Marks the message as edited.
func (u *Update) Withdraw() {
	// other address families (eg. Flowspec): the same NLRI, as MP_UNREACH
	if mp := u.ReachMP(); mp != nil && mp.Prefixes() == nil && u.UnreachMP() == nil {
		if mp.Value != nil {
			mp.Value.Marshal(caps.Caps{}, &u.Msg.Meta)
		}
		un := u.Attrs.Use(attrs.ATTR_MP_UNREACH).(*attrs.MP)
		un.AS, un.Data = mp.AS, slices.Clone(mp.Data)
	}

	reach := slices.Clone(u.AllReach()) // NB: clone, the dropped MP_REACH may be re-used
	u.Reach = nil
	u.Attrs.Drop(attrs.ATTR_MP_REACH)
	u.Msg.Edit() // NB: before AddUnreach, to invalidate the cached AllReach()
	u.AddUnreach(reach...)
	u.Attrs.Filter(attrs.ATTR_MP_UNREACH)
}

// AddUnreach adds all unreachable prefixes to u.
// NB: it will purge non-IPv6 MP_UNREACH attribute if needed (IPv4 unicast prefixes are kept)
func (u *Update) AddUnreach(prefixes ...nlri.Prefix) {
	if len(prefixes) == 0 {
		return
	} else {
		delete(u.cache, "allunreach")
	}

	var mpp *attrs.MPPrefixes
	for i := range prefixes {
		pfx := &prefixes[i]
		if pfx.Addr().Is4() {
			u.Unreach = append(u.Unreach, *pfx)
		} else if pfx.Addr().Is6() {
			if mpp == nil {
				mp := u.Attrs.Use(attrs.ATTR_MP_UNREACH).(*attrs.MP)
				mpp, _ = mp.Value.(*attrs.MPPrefixes)
				if mpp == nil || mp.AS != afi.AS_IPV6_UNICAST {
					if mpp != nil && mp.AS == afi.AS_IPV4_UNICAST {
						u.Unreach = append(u.Unreach, mpp.Prefixes...)
					}
					mpp = attrs.NewMPPrefixes(mp).(*attrs.MPPrefixes)
					mp.AS = afi.AS_IPV6_UNICAST
					mp.Value = mpp
				}
			}
			mpp.Prefixes = append(mpp.Prefixes, *pfx)
		} // else ignore
	}
}

// AsPath returns the AS path from u, or nil if not defined.
func (u *Update) AsPath() (aspath *attrs.Aspath) {
	if ok := u.recache(); !ok {
		return nil // empty
	} else if aspath, ok = u.cache["aspath"].(*attrs.Aspath); ok {
		return aspath
	}

	// AS_PATH must be present and valid
	ap, ok := u.Attrs.Get(attrs.ATTR_ASPATH).(*attrs.Aspath)
	if !ok || !ap.IsValid() {
		u.cache["aspath"] = nil
		return nil // empty
	}
	aspath = ap // AS_PATH looks good so far

	// need to process the AS4_PATH attribute?
	// NB: only for 2-byte AS_PATH, otherwise AS4_PATH must be ignored (RFC 6793 4.1),
	// or a peer could spoof the path seen by eg. ROV/ASPA vs. what the router uses
	if ap4, ok := u.Attrs.Get(attrs.ATTR_AS4PATH).(*attrs.Aspath); ok && ap.As2 {
		switch apl, ap4l := ap.Len(), ap4.Len(); {
		case apl < ap4l: // AS4_PATH is invalid
			aspath = ap
		case apl == ap4l: // AS4_PATH is good as-is
			aspath = ap4
		default: // AS4_PATH is missing the leading part of AS_PATH
			aspath = attrs.NewAspath(ap.CodeFlags).(*attrs.Aspath)

			// start with the missing part of AS_PATH, then append the AS4_PATH
			// NB: preserve AS_SETs, even with 1 member (affects the origin)
			aspath.AppendFrom(ap, apl-ap4l)
			aspath.AppendFrom(ap4, -1)
		}
	}

	u.cache["aspath"] = aspath
	return aspath
}

// NextHop returns NEXT_HOP address, if possible.
// Check nh.IsValid() before using the value.
func (u *Update) NextHop() (nh netip.Addr) {
	if ok := u.recache(); !ok {
		return // empty
	} else if nh, ok = u.cache["nexthop"].(netip.Addr); ok {
		return // nh set from cache
	}

	if mp := u.ReachMP().Prefixes(); mp != nil {
		nh = mp.NextHop.Unmap()
	} else if aip, _ := u.Attrs.Get(attrs.ATTR_NEXTHOP).(*attrs.IP); aip != nil {
		nh = aip.Addr.Unmap()
	} else {
		// nh remains invalid
	}

	u.cache["nexthop"] = nh
	return nh
}

// Origin returns the ATTR_ORIGIN value
func (u *Update) Origin() (origin byte, ok bool) {
	if a, ok := u.Attrs.Get(attrs.ATTR_ORIGIN).(*attrs.Origin); ok {
		return a.Origin, true
	} else {
		return 0, false
	}
}

// Med returns the ATTR_MED value
func (u *Update) Med() (med uint32, ok bool) {
	if a, ok := u.Attrs.Get(attrs.ATTR_MED).(*attrs.U32); ok {
		return a.Val, true
	} else {
		return 0, false
	}
}

// LocalPref returns the ATTR_LOCALPREF value
func (u *Update) LocalPref() (localpref uint32, ok bool) {
	if a, ok := u.Attrs.Get(attrs.ATTR_LOCALPREF).(*attrs.U32); ok {
		return a.Val, true
	} else {
		return 0, false
	}
}

// Otc returns the ATTR_OTC value (Only To Customer, RFC 9234)
func (u *Update) Otc() (otc uint32, ok bool) {
	if a, ok := u.Attrs.Get(attrs.ATTR_OTC).(*attrs.U32); ok {
		return a.Val, true
	} else {
		return 0, false
	}
}

// Community returns the community attribute, or nil if not defined.
func (u *Update) Community() *attrs.Community {
	c, _ := u.Attrs.Get(attrs.ATTR_COMMUNITY).(*attrs.Community)
	return c
}

// ExtCommunity returns the extended community attribute, or nil if not defined.
func (u *Update) ExtCommunity() *attrs.Extcom {
	c, _ := u.Attrs.Get(attrs.ATTR_EXT_COMMUNITY).(*attrs.Extcom)
	return c
}

// LargeCommunity returns the large community attribute, or nil if not defined.
func (u *Update) LargeCommunity() *attrs.LargeCom {
	c, _ := u.Attrs.Get(attrs.ATTR_LARGE_COMMUNITY).(*attrs.LargeCom)
	return c
}
