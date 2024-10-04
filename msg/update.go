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

	Reach    []nlri.NLRI // reachable IPv4 unicast
	Unreach  []nlri.NLRI // unreachable IPv4 unicast
	RawAttrs []byte      // raw attributes

	Attrs attrs.Attrs // parsed attributes
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
	u.RawAttrs = nil
	u.Attrs.Reset()
}

// Parse parses msg.Data as BGP UPDATE,
// in the context of BGP capabilities cps, which can be empty.
func (u *Update) Parse(cps caps.Caps) error {
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

	// witdrawn routes
	if len(withdrawn) > 0 {
		var err error
		u.Unreach, err = nlri.Unmarshal(u.Unreach, withdrawn, afi.AS_IPV4_UNICAST, cps, u.Msg.Dir)
		if err != nil {
			return err
		}
	}

	// take it
	u.RawAttrs = ats
	u.Msg.Upper = UPDATE
	return nil
}

// ParseAttrs parses all attributes from RawAttrs into Attrs.
func (u *Update) ParseAttrs(cps caps.Caps) error {
	var (
		raw  = u.RawAttrs    // all attributes
		atyp attrs.CodeFlags // attribute type
		alen uint16          // attribute length
		ats  attrs.Attrs     // parsed attributes
	)

	ats.Init()
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
	u.RawAttrs = nil

	// marshal one-by-one
	var raw []byte
	u.Attrs.Each(func(i int, ac attrs.Code, at attrs.Attr) {
		raw = at.Marshal(raw, cps, u.Msg.Dir)
	})
	u.RawAttrs = raw
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
	if len(u.RawAttrs) > math.MaxUint16 {
		return fmt.Errorf("Marshal: too long Attributes: %w (%d)", ErrLength, len(u.RawAttrs))
	}
	buf = msb.AppendUint16(buf, uint16(len(u.RawAttrs)))
	buf = append(buf, u.RawAttrs...)

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
	dst = append(dst, '{')

	if len(u.Reach) > 0 {
		dst = append(dst, `"reach":`...)
		dst = nlri.ToJSON(dst, u.Reach)
	}

	if len(u.Unreach) > 0 {
		if len(u.Reach) > 0 {
			dst = append(dst, ',')
		}
		dst = append(dst, `"unreach":`...)
		dst = nlri.ToJSON(dst, u.Unreach)
	}

	if len(u.Reach) > 0 || len(u.Unreach) > 0 {
		dst = append(dst, ',')
	}

	dst = append(dst, `"attrs":`...)
	if u.Attrs.Valid() {
		dst = u.Attrs.ToJSON(dst)
	} else {
		dst = json.Hex(dst, u.RawAttrs)
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
				u.RawAttrs, err = json.UnHex(val, u.RawAttrs[:0])
			} else {
				err = u.Attrs.FromJSON(val)
			}
		}
		return err
	})
}

// MP returns raw MP-BGP attribute ac, or nil
func (u *Update) MP(ac attrs.Code) *attrs.MP {
	if a, ok := u.Attrs.Get(ac).(*attrs.MP); ok {
		return a
	}
	return nil
}

// AS returns the message AFI+SAFI, giving priority to MP-BGP attributes
func (u *Update) AS() afi.AS {
	if u == nil || u.Msg.Upper != UPDATE {
		return afi.AS_INVALID
	} else if reach := u.MP(attrs.ATTR_MP_REACH); reach != nil {
		return reach.AS
	} else if unreach := u.MP(attrs.ATTR_MP_UNREACH); unreach != nil {
		return unreach.AS
	} else {
		return afi.AS_IPV4_UNICAST
	}
}

// HasReach returns true iff u announces reachable NLRI (for any address family AF).
func (u *Update) HasReach() bool {
	if u == nil || u.Msg.Upper != UPDATE {
		return false
	}
	if len(u.Reach) > 0 {
		return true
	}
	if mp := u.MP(attrs.ATTR_MP_REACH).Prefixes(); mp != nil && len(mp.Prefixes) > 0 {
		return true
	}
	return false
}

// GetReach appends all reachable IP prefixes in u to dst (can be nil)
func (u *Update) GetReach(dst []nlri.NLRI) []nlri.NLRI {
	if u == nil || u.Msg.Upper != UPDATE {
		return dst
	}
	dst = append(dst, u.Reach...)
	if mp := u.MP(attrs.ATTR_MP_REACH).Prefixes(); mp != nil && len(mp.Prefixes) > 0 {
		dst = append(dst, mp.Prefixes...)
	}
	return dst
}

// HasUnreach returns true iff u withdraws unreachable NLRI (for any address family AF).
func (u *Update) HasUnreach() bool {
	if u == nil || u.Msg.Upper != UPDATE {
		return false
	}
	if len(u.Unreach) > 0 {
		return true
	}
	if mp := u.MP(attrs.ATTR_MP_UNREACH).Prefixes(); mp != nil && len(mp.Prefixes) > 0 {
		return true
	}
	return false
}

// GetUnreach appends all unreachable IP prefixes in u to dst (can be nil)
func (u *Update) GetUnreach(dst []nlri.NLRI) []nlri.NLRI {
	if u == nil || u.Msg.Upper != UPDATE {
		return dst
	}
	dst = append(dst, u.Unreach...)
	if mp := u.MP(attrs.ATTR_MP_UNREACH).Prefixes(); mp != nil && len(mp.Prefixes) > 0 {
		dst = append(dst, mp.Prefixes...)
	}
	return dst
}

// AsPath returns the ATTR_ASPATH from u, or nil if not defined.
// TODO: support ATTR_AS4PATH
func (u *Update) AsPath() *attrs.Aspath {
	if u == nil || u.Msg.Upper != UPDATE {
		return nil
	} else if ap, ok := u.Attrs.Get(attrs.ATTR_ASPATH).(*attrs.Aspath); ok {
		return ap
	} else {
		return nil
	}
}

// NextHop returns NEXT_HOP address, if possible.
// Check nh.IsValid() before using the value.
func (u *Update) NextHop() (nh netip.Addr) {
	if u == nil || u.Msg.Upper != UPDATE {
		return
	}
	if mp := u.MP(attrs.ATTR_MP_REACH).Prefixes(); mp != nil {
		return mp.NextHop
	}
	if nh, _ := u.Attrs.Get(attrs.ATTR_NEXTHOP).(*attrs.IP); nh != nil {
		return nh.Addr
	}
	return
}
