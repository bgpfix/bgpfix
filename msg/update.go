package msg

import (
	"fmt"
	"math"
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
		u.Reach, err = nlri.Unmarshal(u.Reach, buf, afi.AS_IPV4_UNICAST, cps, &u.Msg.Meta)
		if err != nil {
			return err
		}
	}

	// withdrawn routes
	if len(withdrawn) > 0 {
		var err error
		u.Unreach, err = nlri.Unmarshal(u.Unreach, withdrawn, afi.AS_IPV4_UNICAST, cps, &u.Msg.Meta)
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
		if err := attr.Unmarshal(buf, cps, &u.Msg.Meta); err != nil {
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
		raw = at.Marshal(raw, cps, &u.Msg.Meta)
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
	buf = nlri.Marshal(buf, u.Unreach, afi.AS_IPV4_UNICAST, cps, &u.Msg.Meta)
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
	buf = nlri.Marshal(buf, u.Reach, afi.AS_IPV4_UNICAST, cps, &msg.Meta)

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
	err := json.ObjectEach(src, func(key string, val []byte, typ json.Type) (err error) {
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
	if err != nil {
		return err
	}

	// Path Ids in JSON mean ADD-PATH for their address family, whatever the session caps
	var ap meta.AddPath
	hasId := func(p nlri.Prefix) bool { return p.Add != nil }
	if slices.ContainsFunc(u.Reach, hasId) || slices.ContainsFunc(u.Unreach, hasId) {
		ap.AS = append(ap.AS, afi.AS_IPV4_UNICAST)
	}
	for _, ac := range []attrs.Code{attrs.ATTR_MP_REACH, attrs.ATTR_MP_UNREACH} {
		mp, _ := u.Attrs.Get(ac).(*attrs.MP)
		if p := mp.Prefixes(); p != nil && slices.ContainsFunc(p.Prefixes, hasId) && !ap.Has(mp.AS) {
			ap.AS = append(ap.AS, mp.AS)
		}
	}
	if len(ap.AS) > 0 {
		u.Msg.ParseAddPath = &ap
	}
	return nil
}
