// Package attrs represents BGP path attributes.
//
// This package can store a set of BGP attributes in a thread-unsafe map
// using the Attrs type, and read/write a particular BGP attribute
// representation using implementations of the Attr interface.
package attrs

import (
	"fmt"
	"slices"

	"github.com/bgpfix/bgpfix/binary"
	"github.com/bgpfix/bgpfix/json"
)

var msb = binary.Msb

// Attrs represents a set of BGP path attributes.
// It should not contain nil values.
//
// The set is a short slice sorted by attribute code, as a typical UPDATE has
// only a handful of attributes. Instances of reset attributes are kept for re-use.
//
// Attrs and its values are not thread-safe.
type Attrs struct {
	used []entry // attributes in the set, sorted by code
	free []entry // reset instances for re-use, disjoint by code from used
}

type entry struct {
	code Code
	attr Attr
}

// find returns the position of ac in es, or the position where it should be inserted
func find(es []entry, ac Code) (int, bool) {
	for i := range es {
		if es[i].code >= ac {
			return i, es[i].code == ac
		}
	}
	return len(es), false
}

// dropFree removes ac from ats.free, returning its instance (or nil)
func (ats *Attrs) dropFree(ac Code) Attr {
	for i := range ats.free {
		if ats.free[i].code == ac {
			at := ats.free[i].attr
			n := len(ats.free) - 1
			ats.free[i] = ats.free[n]
			ats.free[n] = entry{}
			ats.free = ats.free[:n]
			return at
		}
	}
	return nil
}

// insert adds at as ac at position i in ats.used
func (ats *Attrs) insert(i int, ac Code, at Attr) {
	ats.used = append(ats.used, entry{})
	copy(ats.used[i+1:], ats.used[i:])
	ats.used[i] = entry{ac, at}
}

// remove resets ats.used[i] and moves it to ats.free
func (ats *Attrs) remove(i int) {
	e := ats.used[i]
	e.attr.Reset()
	ats.free = append(ats.free, e)
	n := len(ats.used) - 1
	copy(ats.used[i:], ats.used[i+1:])
	ats.used[n] = entry{} // NB: drop the stale reference past len
	ats.used = ats.used[:n]
}

// Reset resets Attrs back to initial state.
func (ats *Attrs) Reset() {
	for _, e := range ats.used {
		e.attr.Reset()
	}
	ats.free = append(ats.free, ats.used...)
	clear(ats.used)
	ats.used = ats.used[:0]
}

// Len returns the number of attributes
func (ats *Attrs) Len() int {
	return len(ats.used)
}

// Get returns ats[ac] or nil if not possible.
func (ats *Attrs) Get(ac Code) Attr {
	if i, ok := find(ats.used, ac); ok {
		return ats.used[i].attr
	}
	return nil
}

// Has returns true iff ats[ac] is set and non-nil
func (ats *Attrs) Has(ac Code) bool {
	_, ok := find(ats.used, ac)
	return ok
}

// Set overwrites ats[ac] with value.
func (ats *Attrs) Set(ac Code, value Attr) {
	i, ok := find(ats.used, ac)
	switch {
	case ok && value == nil:
		ats.remove(i)
	case ok:
		ats.used[i].attr = value
	case value != nil:
		ats.dropFree(ac)
		ats.insert(i, ac, value)
	} // else: no-op
}

// Drop drops ats[ac]
func (ats *Attrs) Drop(ac Code) {
	ats.Set(ac, nil)
}

// Filter drops all attributes except those in ac
func (ats *Attrs) Filter(ac ...Code) {
	for i := len(ats.used) - 1; i >= 0; i-- {
		if !slices.Contains(ac, ats.used[i].code) {
			ats.remove(i)
		}
	}
}

// Use returns ats[ac] if its already set and non-nil.
// Otherwise, it adds a new instance for ac with default flags.
func (ats *Attrs) Use(ac Code) Attr {
	i, ok := find(ats.used, ac)
	if ok {
		return ats.used[i].attr // already used
	}

	// re-use existing instance, or create new
	at := ats.dropFree(ac)
	if at == nil {
		at = NewAttr(ac)
	}
	ats.insert(i, ac, at)
	return at
}

// Each executes cb for each attribute in ats,
// in an ascending order of attribute codes.
func (ats *Attrs) Each(cb func(i int, ac Code, at Attr)) {
	for i, e := range ats.used {
		cb(i, e.code, e.attr)
	}
}

func (ats *Attrs) MarshalJSON() ([]byte, error) {
	return ats.ToJSON(nil), nil
}

func (ats *Attrs) ToJSON(dst []byte) []byte {
	if len(ats.used) == 0 {
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

		// {"flags": ..., "value": ...}, or just the value with default flags?
		// NB: one pass over val; on error, fl stays nil and attr.FromJSON(val) reports it
		var fl, v []byte
		if typ == json.OBJECT {
			json.ObjectEach(val, func(k string, kv []byte, _ json.Type) error {
				switch k {
				case "flags":
					fl = kv
				case "value":
					v = kv
				}
				return nil
			})
		}
		if fl != nil {
			var af Flags
			if err := af.FromJSON(fl); err != nil {
				return fmt.Errorf("%w: %w", ErrAttrFlags, err)
			}
			attr.SetFlags(af)
		} else {
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
