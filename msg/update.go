package msg

import (
	"errors"
	"fmt"
	"math"
	"net/netip"

	jsp "github.com/buger/jsonparser"
)

// Update represents a BGP UPDATE message
type Update struct {
	Msg *Msg // parent BGP message

	Reach    []netip.Prefix // reachable IPv4 unicast
	Unreach  []netip.Prefix // unreachable IPv4 unicast
	RawAttrs []byte         // raw attributes

	Attrs Attrs // parsed attributes
	afi   Afi   // AFI from ATTR_MP_REACH / ATTR_MP_UNREACH
	safi  Safi  // SAFI from ATTR_MP_REACH / ATTR_MP_UNREACH
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

	var attrs []byte
	l = msb.Uint16(buf[0:2])
	buf = buf[2:]
	if int(l) > len(buf) {
		return ErrShort
	} else if l > 0 {
		attrs = buf[:l]
		buf = buf[l:]
	}

	announced := buf

	var err error
	if len(announced) > 0 {
		u.Reach, err = appendPrefixes(u.Reach, announced, false)
		if err != nil {
			return err
		}
	}

	if len(withdrawn) > 0 {
		u.Unreach, err = appendPrefixes(u.Unreach, withdrawn, false)
		if err != nil {
			return err
		}
	}

	u.RawAttrs = attrs
	return nil
}

// ParseAttrs parses all attributes from RawAttrs into Attrs.
func (u *Update) ParseAttrs(caps Caps) error {
	var (
		raw   = u.RawAttrs // all attributes
		atyp  AttrType     // attribute type
		alen  uint16       // attribute length
		errs  []error      // atribute errors
		attrs Attrs        // parsed attributes
	)

	attrs.Init()
	for len(raw) > 0 {
		if len(raw) < 3 {
			return ErrAttrs
		}

		// parse attribute type
		atyp = AttrType(msb.Uint16(raw[0:2]))
		acode := atyp.Code()

		// parse attribute length
		if !atyp.HasFlags(ATTR_EXTENDED) {
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
		if attrs.Has(acode) {
			errs = append(errs, fmt.Errorf("%s: %w", acode, ErrDupe))
			continue
		}

		// create, overwrite flags, try parsing
		attr := attrs.Use(acode)
		attr.SetFlags(atyp.Flags())
		if err := attr.Unmarshal(buf, caps); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", acode, err))
		}
	}

	// any errors?
	if len(errs) > 0 {
		return fmt.Errorf("%w: %w", ErrAttrs, errors.Join(errs...))
	}

	// store
	u.Attrs = attrs
	return nil
}

func (u *Update) afisafi() bool {
	if reach, ok := u.Attrs.Get(ATTR_MP_REACH).(*AttrMP); ok {
		u.afi = reach.Afi()
		u.safi = reach.Safi()
		return true
	} else if unreach, ok := u.Attrs.Get(ATTR_MP_UNREACH).(*AttrMP); ok {
		u.afi = unreach.Afi()
		u.safi = unreach.Safi()
		return true
	} else {
		return false
	}
}

// Afi returns the AFI from MP_REACH attribute (or MP_UNREACH)
func (u *Update) Afi() Afi {
	if u.afi > 0 || u.afisafi() {
		return u.afi
	} else {
		return 0
	}
}

// Safi returns the SAFI from MP_REACH attribute (or MP_UNREACH)
func (u *Update) Safi() Safi {
	if u.safi > 0 || u.afisafi() {
		return u.safi
	} else {
		return 0
	}
}

// ReachMP returns ATTR_MP_REACH value from u, or nil if not defined
func (u *Update) ReachMP() AttrMPValue {
	if a, ok := u.Attrs.Get(ATTR_MP_REACH).(*AttrMP); ok {
		return a.Value
	} else {
		return nil
	}
}

// UnreachMP returns ATTR_MP_UNREACH value from u, or nil if not defined
func (u *Update) UnreachMP() AttrMPValue {
	if a, ok := u.Attrs.Get(ATTR_MP_UNREACH).(*AttrMP); ok {
		return a.Value
	} else {
		return nil
	}
}

// MarshalAttrs marshals u.Attrs into u.RawAttrs
func (u *Update) MarshalAttrs(caps Caps) error {
	// NB: avoid u.RawAttrs[:0] as it might be referencing another slice
	u.RawAttrs = nil

	// marshal one-by-one
	var raw []byte
	u.Attrs.Each(func(i int, ac AttrCode, att Attr) {
		raw = att.Marshal(raw, caps)
	})
	u.RawAttrs = raw
	return nil
}

// Marshal marshals o to o.Msg and returns it
func (u *Update) Marshal(caps Caps) error {
	msg := u.Msg
	msg.Data = nil
	dst := msg.buf[:0]

	// withdrawn routes
	dst = append(dst, 0, 0) // length (tbd [1])
	dst = marshalPrefixes(dst, u.Unreach)
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
	dst = marshalPrefixes(dst, u.Reach)

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
		dst = jsonPrefixes(dst, u.Reach)
	}

	if len(u.Unreach) > 0 {
		if len(u.Reach) > 0 {
			dst = append(dst, ',')
		}
		dst = append(dst, `"unreach":`...)
		dst = jsonPrefixes(dst, u.Unreach)
	}

	if len(u.Reach) > 0 || len(u.Unreach) > 0 {
		dst = append(dst, ',')
	}

	dst = append(dst, `"attrs":`...)
	if u.Attrs.Valid() {
		dst = u.Attrs.ToJSON(dst)
	} else {
		dst = jsonHex(dst, u.RawAttrs)
	}

	dst = append(dst, '}')
	return dst
}

// FromJSON reads u JSON representation from src
func (u *Update) FromJSON(src []byte) error {
	return jsp.ObjectEach(src, func(key, val []byte, typ jsp.ValueType, _ int) (err error) {
		switch bs(key) {
		case "reach":
			u.Reach, err = unjsonPrefixes(u.Reach[:0], val)
		case "unreach":
			u.Unreach, err = unjsonPrefixes(u.Unreach[:0], val)
		case "attrs":
			if typ == jsp.String {
				u.RawAttrs, err = unjsonHex(u.RawAttrs[:0], val)
			} else if typ == jsp.Object {
				err = u.Attrs.FromJSON(val)
			}
		}

		if err != nil {
			return fmt.Errorf("update[%s]: %w", key, err)
		} else {
			return nil
		}
	})
}
