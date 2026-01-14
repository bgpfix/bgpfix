package msg

import (
	"fmt"
	"math"
	"net/netip"

	"github.com/bgpfix/bgpfix/afi"
	"github.com/bgpfix/bgpfix/attrs"
	"github.com/bgpfix/bgpfix/caps"
	"github.com/bgpfix/bgpfix/json"
	"github.com/bgpfix/bgpfix/nlri"
)

// Update represents a BGP UPDATE message
type Update struct {
	Msg *Msg // parent BGP message

	Reach   []nlri.NLRI // reachable IPv4 unicast
	Unreach []nlri.NLRI // unreachable IPv4 unicast

	AttrsRaw []byte      // raw attributes, referencing Msg.Data
	Attrs    attrs.Attrs // parsed attributes

	cached int            // msg.Version for which the cache is valid
	cache  map[string]any // cached message attributes
}

const (
	UPDATE_MINLEN = 23 - HEADLEN // rfc4271/4.3
)

// Init initializes u to use parent m
func (u *Update) Init(m *Msg) {
	u.Msg = m
}

// Reset prepares u for re-use
func (u *Update) Reset() {
	u.Unreach = u.Unreach[:0]
	u.Reach = u.Reach[:0]
	u.AttrsRaw = nil
	u.Attrs.Reset()
	u.cached = 0
	clear(u.cache)
}

// recache makes sure we can still use the cache values (or drops the cache)
func (u *Update) recache() bool {
	if u == nil || u.Msg.Upper != UPDATE {
		return false
	} else if u.cache == nil {
		u.cache = make(map[string]any)
		u.cached = u.Msg.Version
	} else if u.Msg.Version != u.cached {
		clear(u.cache)
		u.cached = u.Msg.Version
	}
	return true
}

// Parse parses msg.Data as BGP UPDATE,
// in the context of BGP capabilities cps, which can be empty.
func (u *Update) Parse(cps caps.Caps) error {
	u.Reset()

	buf := u.Msg.Data
	if len(buf) < UPDATE_MINLEN {
		return ErrShort
	}

	// withdrawn routes - prepare
	var withdrawn []byte
	l := msb.Uint16(buf[0:2])
	buf = buf[2:]
	if int(l)+2 > len(buf) {
		return ErrShort
	} else if l > 0 {
		withdrawn = buf[:l]
		buf = buf[l:]
	}

	// attributes
	var ats []byte
	l = msb.Uint16(buf[0:2])
	buf = buf[2:]
	if int(l) > len(buf) {
		return ErrShort
	} else if l > 0 {
		ats = buf[:l]
		buf = buf[l:]
	}

	// announced routes
	if len(buf) > 0 {
		var err error
		u.Reach, err = nlri.Unmarshal(u.Reach, buf, afi.AS_IPV4_UNICAST, cps, u.Msg.Dir)
		if err != nil {
			return err
		}
	}

	// withdrawn routes
	if len(withdrawn) > 0 {
		var err error
		u.Unreach, err = nlri.Unmarshal(u.Unreach, withdrawn, afi.AS_IPV4_UNICAST, cps, u.Msg.Dir)
		if err != nil {
			return err
		}
	}

	// take it
	u.AttrsRaw = ats
	u.Msg.Upper = UPDATE
	return nil
}

// ParseAttrs parses all attributes from RawAttrs into Attrs.
func (u *Update) ParseAttrs(cps caps.Caps) error {
	var (
		raw  = u.AttrsRaw    // all attributes
		atyp attrs.CodeFlags // attribute type
		alen uint16          // attribute length
		ats  attrs.Attrs     // parsed attributes
	)

	for len(raw) > 0 {
		if len(raw) < 3 {
			return ErrAttrs
		}

		// parse attribute type
		atyp = attrs.CodeFlags(msb.Uint16(raw[0:2]))
		acode := atyp.Code()
		if ats.Has(acode) {
			return fmt.Errorf("%s: %w", acode, ErrAttrDupe)
		}

		// parse attribute length
		if !atyp.HasFlags(attrs.ATTR_EXTENDED) {
			alen = uint16(raw[2])
			raw = raw[3:]
		} else if len(raw) < 4 {
			return ErrParams
		} else { // extended length
			alen = msb.Uint16(raw[2:4])
			raw = raw[4:]
		}
		if len(raw) < int(alen) {
			return ErrAttrs
		}

		// put attribute value in buf, skip raw to next
		buf := raw[:alen]
		raw = raw[alen:]

		// create, overwrite flags, try parsing
		attr := ats.Use(acode)
		attr.SetFlags(atyp.Flags())
		if err := attr.Unmarshal(buf, cps, u.Msg.Dir); err != nil {
			return fmt.Errorf("%s: %w", acode, err)
		}
	}

	// store
	u.Attrs = ats
	return nil
}

// MarshalAttrs marshals u.Attrs into u.RawAttrs
func (u *Update) MarshalAttrs(cps caps.Caps) error {
	// NB: avoid u.RawAttrs[:0] as it might be referencing another slice
	u.AttrsRaw = nil

	// marshal one-by-one
	var raw []byte
	u.Attrs.Each(func(i int, ac attrs.Code, at attrs.Attr) {
		raw = at.Marshal(raw, cps, u.Msg.Dir)
	})
	u.AttrsRaw = raw
	return nil
}

// Marshal marshals u to u.Msg.Data.
func (u *Update) Marshal(cps caps.Caps) error {
	msg := u.Msg
	buf := msg.buf[:0]

	// withdrawn routes
	buf = append(buf, 0, 0) // length (tbd [1])
	buf = nlri.Marshal(buf, u.Unreach, afi.AS_IPV4_UNICAST, cps, u.Msg.Dir)
	if l := len(buf) - 2; l > math.MaxUint16 {
		return fmt.Errorf("Marshal: too long Withdrawn Routes: %w (%d)", ErrLength, l)
	} else if l > 0 {
		msb.PutUint16(buf, uint16(l)) // [1]
	}

	// attributes
	if len(u.AttrsRaw) > math.MaxUint16 {
		return fmt.Errorf("Marshal: too long Attributes: %w (%d)", ErrLength, len(u.AttrsRaw))
	}
	buf = msb.AppendUint16(buf, uint16(len(u.AttrsRaw)))
	buf = append(buf, u.AttrsRaw...)

	// announced routes
	buf = nlri.Marshal(buf, u.Reach, afi.AS_IPV4_UNICAST, cps, msg.Dir)

	// done
	msg.Type = UPDATE
	msg.Upper = UPDATE
	msg.buf = buf
	msg.Data = buf
	msg.ref = false
	return nil
}

// String dumps u to JSON
func (u *Update) String() string {
	return string(u.ToJSON(nil))
}

// ToJSON appends JSON representation of u to dst (may be nil)
func (u *Update) ToJSON(dst []byte) []byte {
	comma := false
	dst = append(dst, '{')

	if len(u.Reach) > 0 {
		dst = append(dst, `"reach":`...)
		dst = nlri.ToJSON(dst, u.Reach)
		comma = true
	}

	if len(u.Unreach) > 0 {
		if comma {
			dst = append(dst, ',')
		} else {
			comma = true
		}
		dst = append(dst, `"unreach":`...)
		dst = nlri.ToJSON(dst, u.Unreach)
	}

	if al := u.Attrs.Len() > 0; al || len(u.AttrsRaw) > 0 {
		if comma {
			dst = append(dst, ',')
		} else {
			comma = true
		}
		dst = append(dst, `"attrs":`...)
		if al {
			dst = u.Attrs.ToJSON(dst)
		} else {
			dst = json.Hex(dst, u.AttrsRaw)
		}
	}

	dst = append(dst, '}')
	return dst
}

// FromJSON reads u JSON representation from src
func (u *Update) FromJSON(src []byte) error {
	return json.ObjectEach(src, func(key string, val []byte, typ json.Type) (err error) {
		switch key {
		case "reach":
			u.Reach, err = nlri.FromJSON(val, u.Reach[:0])
		case "unreach":
			u.Unreach, err = nlri.FromJSON(val, u.Unreach[:0])
		case "attrs":
			if typ == json.STRING {
				u.AttrsRaw, err = json.UnHex(val, u.AttrsRaw[:0])
			} else {
				err = u.Attrs.FromJSON(val)
			}
		}
		return err
	})
}

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
func (u *Update) AllReach() []nlri.NLRI {
	if !u.recache() {
		return nil
	}

	all, ok := u.cache["allreach"].([]nlri.NLRI)
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
		all = make([]nlri.NLRI, 0, len(u.Reach)+len(mp.Prefixes))
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
func (u *Update) AddReach(prefixes ...nlri.NLRI) {
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
func (u *Update) AllUnreach() []nlri.NLRI {
	if !u.recache() {
		return nil
	}

	all, ok := u.cache["allunreach"].([]nlri.NLRI)
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
		all = make([]nlri.NLRI, 0, len(u.Unreach)+len(mp.Prefixes))
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

// AddUnreach adds all unreachable prefixes to u.
// NB: it might purge existing MP_UNREACH attribute value if needed
func (u *Update) AddUnreach(prefixes ...nlri.NLRI) {
	if len(prefixes) == 0 {
		return
	} else {
		delete(u.cache, "allunreach")
	}

	// need to use MP?
	var mp *attrs.MP
	var mpp *attrs.MPPrefixes
	if u.Attrs.Has(attrs.ATTR_MP_REACH) || u.Attrs.Has(attrs.ATTR_MP_UNREACH) {
		mp = u.Attrs.Use(attrs.ATTR_MP_UNREACH).(*attrs.MP)
		mpp, _ = mp.Value.(*attrs.MPPrefixes)
	}

	check_mp := func(as afi.AS) {
		if mpp == nil || mp.AS != as {
			mpp = attrs.NewMPPrefixes(mp).(*attrs.MPPrefixes)
			mp.AS = as
			mp.Value = mpp
		}
	}

	for i := range prefixes {
		pfx := &prefixes[i]
		if pfx.Addr().Is4() {
			// can skip BGP-MP?
			if mp == nil {
				u.Unreach = append(u.Unreach, *pfx)
				continue
			}
			check_mp(afi.AS_IPV4_UNICAST)
		} else if pfx.Addr().Is6() {
			check_mp(afi.AS_IPV6_UNICAST)
		} else {
			continue // ignore
		}

		mpp.Prefixes = append(mpp.Prefixes, *pfx)
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

	// need to process the AS4_PATH	attribute?
	if ap4, ok := u.Attrs.Get(attrs.ATTR_AS4PATH).(*attrs.Aspath); ok {
		switch apl, ap4l := ap.Len(), ap4.Len(); {
		case apl < ap4l: // AS4_PATH is invalid
			aspath = ap
		case apl == ap4l: // AS4_PATH is good as-is
			aspath = ap4
		default: // AS4_PATH is missing the leading part of AS_PATH
			aspath = attrs.NewAspath(ap.CodeFlags).(*attrs.Aspath)

			// start with the missing part of AS_PATH
			diff := apl - ap4l
			for i, hop := range ap.Hops() {
				if i >= diff {
					break
				}
				aspath.Append(hop)
			}

			// append the AS4_PATH
			for _, hop := range ap4.Hops() {
				aspath.Append(hop)
			}
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
