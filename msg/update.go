package msg

import (
	"fmt"
	"math"
	"net/netip"
	"slices"

	"github.com/bgpfix/bgpfix/afi"
	"github.com/bgpfix/bgpfix/attrs"
	"github.com/bgpfix/bgpfix/caps"
	"github.com/bgpfix/bgpfix/json"
	"github.com/bgpfix/bgpfix/meta"
	"github.com/bgpfix/bgpfix/nlri"
)

// Update represents a BGP UPDATE message
type Update struct {
	Msg *Msg // parent BGP message

	Reach   []nlri.Prefix // reachable IPv4 unicast
	Unreach []nlri.Prefix // unreachable IPv4 unicast

	AttrsRaw []byte      // raw attributes, referencing Msg.Data
	Attrs    attrs.Attrs // parsed attributes

	attrsBuf []byte // owned scratch buffer for MarshalAttrs, backs AttrsRaw after Marshal

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
		u.Reach, err = nlri.Unmarshal(u.Reach, buf, afi.AS_IPV4_UNICAST, cps, u.Msg.Meta)
		if err != nil {
			return err
		}
	}

	// withdrawn routes
	if len(withdrawn) > 0 {
		var err error
		u.Unreach, err = nlri.Unmarshal(u.Unreach, withdrawn, afi.AS_IPV4_UNICAST, cps, u.Msg.Meta)
		if err != nil {
			return err
		}
	}

	// take it
	u.AttrsRaw = ats
	u.Msg.Upper = UPDATE
	return nil
}

// ParseAttrs parses all attributes from AttrsRaw into Attrs.
// On error, Attrs is left empty.
func (u *Update) ParseAttrs(cps caps.Caps) (err error) {
	defer func() {
		if err != nil {
			u.Attrs.Reset()
		}
	}()

	// allowed to guess the ASN size? if not, just parse per session caps
	// NB: record the guess in ParseAS4, so that writers know the real encoding
	if u.Msg.ParseAS4 != 0 || !cps.Has(caps.CAP_AS4) || !cps.Has(caps.CAP_AS_GUESS) {
		return u.parseAttrs(cps)
	}

	// do the attributes suggest 2-byte ASNs? AS4_PATH or AS4_AGGREGATOR present
	// (RFC 6793), or a 6-byte AGGREGATOR; NB: walk the headers only
	as2 := false
	for raw := u.AttrsRaw; !as2; {
		atyp, val, rest, ok := nextAttr(raw)
		if !ok {
			break
		}
		switch atyp.Code() {
		case attrs.ATTR_AS4PATH, attrs.ATTR_AS4AGGREGATOR:
			as2 = true
		case attrs.ATTR_AGGREGATOR:
			as2 = len(val) == 6
		}
		raw = rest
	}

	// try 4-byte ASNs first?
	// NB: some 2-byte AS_PATHs also parse as valid 4-byte ones (eg. a sequence of n ASNs
	// followed by a set of n-1 ASNs), so 4-byte success alone does not prove anything:
	// also require no ASNs in the unallocated space between 2^20 and the private range
	if !as2 && u.parseAttrs(cps) == nil {
		ap, _ := u.Attrs.Get(attrs.ATTR_ASPATH).(*attrs.Aspath)
		plausible := true
		for i := 0; ap != nil && i < len(ap.Segments) && plausible; i++ {
			for _, asn := range ap.Segments[i].List {
				if asn >= 1<<20 && asn < 4200000000 {
					plausible = false
					break
				}
			}
		}
		if plausible {
			return nil // 4-byte, looks good
		}
	}

	// try 2-byte ASNs
	u.Msg.ParseAS4 = -1
	if u.parseAttrs(cps) == nil {
		return nil
	}

	// fall back to 4-byte
	u.Msg.ParseAS4 = 0
	return u.parseAttrs(cps)
}

// parseAll parses u, then its attributes
func (u *Update) parseAll(cps caps.Caps) error {
	if err := u.Parse(cps); err != nil {
		return err
	}
	return u.ParseAttrs(cps)
}

// guessAddPath is called after parsing u, with err as the result.
// If it failed, or the first prefix of any NLRI list is /0 (rare in real data, but
// what a small ADD-PATH Path Id reads as without ADD-PATH), and CAP_ADDPATH_GUESS
// is in cps, it checks the unicast NLRI in msg.Data for ADD-PATH Path Identifiers.
// Iff that contradicts msg.HasAddPath(), it parses u again with u.Msg.ParseAddPath
// set to what the data says, and keeps that iff successful. Returns the final result.
func (u *Update) guessAddPath(cps caps.Caps, err error) error {
	if !cps.Has(caps.CAP_ADDPATH_GUESS) {
		return err
	}

	// NB: this must be O(1) for valid messages, so check the first prefixes only
	if err == nil {
		var mpr, mpu []nlri.Prefix
		if mp := u.ReachMP().Prefixes(); mp != nil {
			mpr = mp.Prefixes
		}
		if mp := u.UnreachMP().Prefixes(); mp != nil {
			mpu = mp.Prefixes
		}
		suspect := false
		for _, pfx := range [4][]nlri.Prefix{u.Reach, u.Unreach, mpr, mpu} {
			suspect = suspect || len(pfx) > 0 && pfx[0].Bits() == 0
		}
		if !suspect {
			return err
		}
	}

	// split msg.Data, see Parse
	m := u.Msg
	buf := m.Data
	if len(buf) < UPDATE_MINLEN {
		return err
	}
	l := int(msb.Uint16(buf))
	if 2+l+2 > len(buf) {
		return err
	}
	wdr, buf := buf[2:2+l], buf[2+l:]
	l = int(msb.Uint16(buf))
	if 2+l > len(buf) {
		return err
	}
	ats, reach := buf[2:2+l], buf[2+l:]

	// the new ParseAddPath, for all address families in the message
	var (
		ap      meta.AddPath
		changed bool
		seen    [2]bool // IPv4/IPv6 unicast already checked?
	)

	// check unicast NLRI in src for address family as
	check := func(as afi.AS, src []byte) {
		i := 0
		if as == afi.AS_IPV6_UNICAST {
			i = 1
		}
		if len(src) == 0 || seen[i] {
			return
		}
		seen[i] = true

		// trust the message, unless the data clearly says otherwise
		has := m.HasAddPath(as, cps)
		if !nlri.Check(src, i == 1, has) && nlri.Check(src, i == 1, !has) {
			has = !has
			changed = true
		}
		if has {
			ap.AS = append(ap.AS, as)
		}
	}

	// check IPv4 NLRI, then walk the attributes for MP_*
	check(afi.AS_IPV4_UNICAST, reach)
	check(afi.AS_IPV4_UNICAST, wdr)
	for {
		atyp, val, rest, ok := nextAttr(ats)
		if !ok {
			break
		}
		ats = rest

		code := atyp.Code()
		if (code != attrs.ATTR_MP_REACH && code != attrs.ATTR_MP_UNREACH) || len(val) < 3 {
			continue
		}
		as := afi.NewASBytes(val[0:3])
		switch {
		case as != afi.AS_IPV4_UNICAST && as != afi.AS_IPV6_UNICAST:
			if m.HasAddPath(as, cps) { // not checked, keep as-is
				ap.AS = append(ap.AS, as)
			}
		case code == attrs.ATTR_MP_UNREACH: // afi, safi, nlri
			check(as, val[3:])
		case len(val) >= 4 && len(val) >= 5+int(val[3]): // afi, safi, nh len, nh, reserved, nlri
			check(as, val[5+int(val[3]):])
		}
	}

	if !changed {
		return err
	}

	// retry with the guess, roll back if no better; NB: rare, so allocate
	old := m.ParseAddPath
	m.ParseAddPath = &ap
	if u.parseAll(cps) == nil {
		return nil
	}
	m.ParseAddPath = old
	if err == nil {
		err = u.parseAll(cps)
	}
	return err
}

// nextAttr splits the first attribute off raw: returns its type, value, and the rest.
// Returns ok=false if raw is empty or truncated.
func nextAttr(raw []byte) (atyp attrs.CodeFlags, val, rest []byte, ok bool) {
	if len(raw) < 3 {
		return
	}
	atyp = attrs.CodeFlags(msb.Uint16(raw[0:2]))
	alen, hl := int(raw[2]), 3
	if atyp.HasFlags(attrs.ATTR_EXTENDED) {
		if len(raw) < 4 {
			return
		}
		alen, hl = int(msb.Uint16(raw[2:4])), 4
	}
	if len(raw) < hl+alen {
		return
	}
	return atyp, raw[hl : hl+alen], raw[hl+alen:], true
}

func (u *Update) parseAttrs(cps caps.Caps) error {
	// NB: Reset keeps Attr objects for re-use
	ats := &u.Attrs
	ats.Reset()

	for raw := u.AttrsRaw; len(raw) > 0; {
		atyp, buf, rest, ok := nextAttr(raw)
		if !ok {
			return ErrAttrs
		}
		raw = rest

		acode := atyp.Code()
		if ats.Has(acode) {
			return fmt.Errorf("%s: %w", acode, ErrAttrDupe)
		}

		// create, overwrite flags, try parsing
		attr := ats.Use(acode)
		attr.SetFlags(atyp.Flags())
		if err := attr.Unmarshal(buf, cps, u.Msg.Meta); err != nil {
			return fmt.Errorf("%s: %w", acode, err)
		}
	}

	return nil
}

// MarshalAttrs marshals u.Attrs into u.AttrsRaw
func (u *Update) MarshalAttrs(cps caps.Caps) error {
	// NB: avoid u.AttrsRaw[:0], it might reference a borrowed slice
	u.AttrsRaw = nil

	// marshal one-by-one
	raw := u.attrsBuf[:0]
	u.Attrs.Each(func(i int, ac attrs.Code, at attrs.Attr) {
		raw = at.Marshal(raw, cps, u.Msg.Meta)
	})
	u.attrsBuf = raw
	u.AttrsRaw = raw
	return nil
}

// Marshal marshals u to u.Msg.Data.
func (u *Update) Marshal(cps caps.Caps) error {
	msg := u.Msg
	buf := msg.buf[:0]

	// withdrawn routes
	buf = append(buf, 0, 0) // length (tbd [1])
	buf = nlri.Marshal(buf, u.Unreach, afi.AS_IPV4_UNICAST, cps, u.Msg.Meta)
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
	buf = nlri.Marshal(buf, u.Reach, afi.AS_IPV4_UNICAST, cps, msg.Meta)

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

	if u.Attrs.Len() > 0 || len(u.AttrsRaw) > 0 {
		if comma {
			dst = append(dst, ',')
		} else {
			comma = true
		}
		dst = append(dst, `"attrs":`...)
		if u.Attrs.Len() > 0 {
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
	reach := slices.Clone(u.Reach)
	u.Reach = nil
	if mp := u.ReachMP().Prefixes(); mp != nil {
		reach = append(reach, mp.Prefixes...)
	}
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
