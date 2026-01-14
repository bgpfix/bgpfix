// Package attrs represents BGP path attributes.
//
// This package can store a set of BGP attributes in a thread-unsafe map
// using the Attrs type, and read/write a particular BGP attribute
// representation using implementations of the Attr interface.
package attrs

import (
	"fmt"

	"github.com/bgpfix/bgpfix/binary"
	"github.com/bgpfix/bgpfix/json"
)

var msb = binary.Msb

// Attrs is an ordinary map that represents a set of BGP path attributes.
// It should not contain nil values.
//
// Attrs and its values are not thread-safe.
type Attrs struct {
	use  [256]bool // indicates whether attribute code is used
	attr [256]Attr // map of attribute code to attribute value
	len  int       // number of attributes used
}

// Reset resets Attrs back to initial state.
func (ats *Attrs) Reset() {
	for ac, use := range ats.use {
		if use {
			ats.attr[ac].Reset()
		}
	}
	ats.use = [256]bool{}
	ats.len = 0
}

// Len returns the number of attributes
func (ats *Attrs) Len() int {
	return ats.len
}

// Get returns ats[ac] or nil if not possible.
func (ats *Attrs) Get(ac Code) Attr {
	if ats.use[ac] {
		return ats.attr[ac]
	} else {
		return nil
	}
}

// Has returns true iff ats[ac] is set and non-nil
func (ats *Attrs) Has(ac Code) bool {
	return ats.use[ac]
}

// Set overwrites ats[ac] with value.
func (ats *Attrs) Set(ac Code, value Attr) {
	if !ats.use[ac] {
		if value != nil {
			ats.use[ac] = true
			ats.len++
			ats.attr[ac] = value
		} // else: no-op
	} else { // = already used
		if value == nil {
			ats.use[ac] = false
			ats.len--
			ats.attr[ac].Reset()
		} else {
			ats.attr[ac] = value
		}
	}
}

// Drop drops ats[ac]
func (ats *Attrs) Drop(ac Code) {
	ats.Set(ac, nil)
}

// Filter drops all attributes except those in ac
func (ats *Attrs) Filter(ac ...Code) {
	keep := make(map[int]bool, len(ac))
	for _, c := range ac {
		keep[int(c)] = true
	}
	for ac, use := range ats.use {
		if use && !keep[ac] {
			ats.use[ac] = false
			ats.len--
			ats.attr[ac].Reset()
		}
	}
}

// Use returns ats[ac] if its already set and non-nil.
// Otherwise, it adds a new instance for ac with default flags.
func (ats *Attrs) Use(ac Code) Attr {
	if ats.use[ac] {
		// already used
		return ats.attr[ac]
	} else if at := ats.attr[ac]; at != nil {
		// re-use existing instance
		ats.len++
		ats.use[ac] = true
		return at
	} else { // = at == nil
		// create new, store, and return
		ats.len++
		at = NewAttr(ac)
		ats.attr[ac] = at
		ats.use[ac] = true
		return at
	}
}

// Each executes cb for each attribute in ats,
// in an ascending order of attribute codes.
func (ats *Attrs) Each(cb func(i int, ac Code, at Attr)) {
	i := 0
	for ac, used := range ats.use {
		if used {
			cb(i, Code(ac), ats.attr[ac])
			i++
		}
	}
}

func (ats *Attrs) MarshalJSON() ([]byte, error) {
	return ats.ToJSON(nil), nil
}

func (ats *Attrs) ToJSON(dst []byte) []byte {
	if ats.len == 0 {
		return append(dst, "{}"...)
	}

	dst = append(dst, '{')
	ats.Each(func(i int, ac Code, at Attr) {
		if i > 0 {
			dst = append(dst, ',')
		}
		dst = ac.ToJSON(dst)

		dst = append(dst, `:{"flags":`...)
		dst = at.Flags().ToJSON(dst)

		dst = append(dst, `,"value":`...)
		dst = at.ToJSON(dst)
		dst = append(dst, '}')
	})
	return append(dst, '}')
}

func (ats *Attrs) FromJSON(src []byte) error {
	return json.ObjectEach(src, func(key string, val []byte, typ json.Type) error {
		// is key a valid attribute code?
		var acode Code
		if err := acode.FromJSON(key); err != nil {
			return fmt.Errorf("%w: %w", ErrAttrCode, err)
		}
		attr := ats.Use(acode)

		// has flags?
		v := json.Get(val, "flags")
		if v != nil {
			var af Flags
			if err := af.FromJSON(v); err != nil {
				return fmt.Errorf("%w: %w", ErrAttrFlags, err)
			}
			attr.SetFlags(af)

			// fetch the value
			v = json.Get(val, "value")
		} else {
			// no flags (use defults), try to use the whole val
			v = val
		}

		// has the value?
		if len(v) == 0 {
			return ErrAttrValue
		}

		// parse?
		if err := attr.FromJSON(v); err != nil {
			return err
		}

		// success!
		return nil
	})
}
