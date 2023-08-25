package msg

import (
	"errors"
	"fmt"
	"math"
	"net/netip"

	"github.com/bgpfix/bgpfix/af"
	"github.com/bgpfix/bgpfix/attrs"
	"github.com/bgpfix/bgpfix/caps"
	"github.com/bgpfix/bgpfix/json"
)

// Update represents a BGP UPDATE message
type Update struct {
	Msg *Msg // parent BGP message

	Reach    []netip.Prefix // reachable IPv4 unicast
	Unreach  []netip.Prefix // unreachable IPv4 unicast
	RawAttrs []byte         // raw attributes

	Attrs attrs.Attrs // parsed attributes
	afi   af.AFI      // AFI from attr.ATTR_MP_REACH / attr.ATTR_MP_UNREACH
	safi  af.SAFI     // SAFI from attr.ATTR_MP_REACH / attr.ATTR_MP_UNREACH
}

const (
	UPDATE_MINLEN = 23 - MSG_HEADLEN // rfc4271/4.3
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
	u.afi = 0
	u.safi = 0
}

// Parse parses msg.Data as BGP UPDATE
func (u *Update) Parse() error {
	buf := u.Msg.Data
	if len(buf) < UPDATE_MINLEN {
		return ErrShort
	}

	var withdrawn []byte
	l := msb.Uint16(buf[0:2])
	buf = buf[2:]
	if int(l)+2 > len(buf) {
		return ErrShort
	} else if l > 0 {
		withdrawn = buf[:l]
		buf = buf[l:]
	}

	var ats []byte
	l = msb.Uint16(buf[0:2])
	buf = buf[2:]
	if int(l) > len(buf) {
		return ErrShort
	} else if l > 0 {
		ats = buf[:l]
		buf = buf[l:]
	}

	announced := buf

	var err error
	if len(announced) > 0 {
		u.Reach, err = attrs.ReadPrefixes(u.Reach, announced, false)
		if err != nil {
			return err
		}
	}

	if len(withdrawn) > 0 {
		u.Unreach, err = attrs.ReadPrefixes(u.Unreach, withdrawn, false)
		if err != nil {
			return err
		}
	}

	u.RawAttrs = ats
	return nil
}

// ParseAttrs parses all attributes from RawAttrs into Attrs.
func (u *Update) ParseAttrs(cps caps.Caps) error {
	var (
		raw  = u.RawAttrs    // all attributes
		atyp attrs.CodeFlags // attribute type
		alen uint16          // attribute length
		errs []error         // atribute errors
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

		// a duplicate?
		if ats.Has(acode) {
			errs = append(errs, fmt.Errorf("%s: %w", acode, ErrDupe))
			continue
		}

		// create, overwrite flags, try parsing
		attr := ats.Use(acode)
		attr.SetFlags(atyp.Flags())
		if err := attr.Unmarshal(buf, cps); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", acode, err))
		}
	}

	// any errors?
	if len(errs) > 0 {
		return fmt.Errorf("%w: %w", ErrAttrs, errors.Join(errs...))
	}

	// store
	u.Attrs = ats
	return nil
}

func (u *Update) afisafi() bool {
	if reach, ok := u.Attrs.Get(attrs.ATTR_MP_REACH).(*attrs.MP); ok {
		u.afi = reach.Afi()
		u.safi = reach.Safi()
		return true
	} else if unreach, ok := u.Attrs.Get(attrs.ATTR_MP_UNREACH).(*attrs.MP); ok {
		u.afi = unreach.Afi()
		u.safi = unreach.Safi()
		return true
	} else {
		return false
	}
}

// Afi returns the AFI from MP_REACH attribute (or MP_UNREACH)
func (u *Update) Afi() af.AFI {
	if u.afi > 0 || u.afisafi() {
		return u.afi
	} else {
		return 0
	}
}

// Safi returns the SAFI from MP_REACH attribute (or MP_UNREACH)
func (u *Update) Safi() af.SAFI {
	if u.safi > 0 || u.afisafi() {
		return u.safi
	} else {
		return 0
	}
}

// ReachMP returns attr.ATTR_MP_REACH value from u, or nil if not defined
func (u *Update) ReachMP() attrs.MPValue {
	if a, ok := u.Attrs.Get(attrs.ATTR_MP_REACH).(*attrs.MP); ok {
		return a.Value
	} else {
		return nil
	}
}

// UnreachMP returns attr.ATTR_MP_UNREACH value from u, or nil if not defined
func (u *Update) UnreachMP() attrs.MPValue {
	if a, ok := u.Attrs.Get(attrs.ATTR_MP_UNREACH).(*attrs.MP); ok {
		return a.Value
	} else {
		return nil
	}
}

// MarshalAttrs marshals u.Attrs into u.RawAttrs
func (u *Update) MarshalAttrs(cps caps.Caps) error {
	// NB: avoid u.RawAttrs[:0] as it might be referencing another slice
	u.RawAttrs = nil

	// marshal one-by-one
	var raw []byte
	u.Attrs.Each(func(i int, ac attrs.Code, at attrs.Attr) {
		raw = at.Marshal(raw, cps)
	})
	u.RawAttrs = raw
	return nil
}

// Marshal marshals o to o.Msg and returns it
func (u *Update) Marshal(cps caps.Caps) error {
	msg := u.Msg
	msg.Data = nil
	dst := msg.buf[:0]

	// withdrawn routes
	dst = append(dst, 0, 0) // length (tbd [1])
	dst = attrs.WritePrefixes(dst, u.Unreach)
	if l := len(dst) - 2; l > math.MaxUint16 {
		return fmt.Errorf("Marshal: too long Withdrawn Routes: %w (%d)", ErrLength, l)
	} else if l > 0 {
		msb.PutUint16(dst, uint16(l)) // [1]
	}

	// attributes
	if len(u.RawAttrs) > math.MaxUint16 {
		return fmt.Errorf("Marshal: too long Attributes: %w (%d)", ErrLength, len(u.RawAttrs))
	}
	dst = msb.AppendUint16(dst, uint16(len(u.RawAttrs)))
	dst = append(dst, u.RawAttrs...)

	// NLRI
	dst = attrs.WritePrefixes(dst, u.Reach)

	// done
	msg.buf = dst
	msg.Data = dst
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
		dst = json.Prefixes(dst, u.Reach)
	}

	if len(u.Unreach) > 0 {
		if len(u.Reach) > 0 {
			dst = append(dst, ',')
		}
		dst = append(dst, `"unreach":`...)
		dst = json.Prefixes(dst, u.Unreach)
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
			u.Reach, err = json.UnPrefixes(val, u.Reach[:0])
		case "unreach":
			u.Unreach, err = json.UnPrefixes(val, u.Unreach[:0])
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
