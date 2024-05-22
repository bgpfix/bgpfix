// Package attrs represents BGP path attributes.
//
// This package can store a set of BGP attributes in a thread-unsafe map
// using the Attrs type, and read/write a particular BGP attribute
// representation using implementations of the Attr interface.
package attrs

import (
	"fmt"
	"sort"

	"github.com/bgpfix/bgpfix/binary"
	"github.com/bgpfix/bgpfix/json"
)

var msb = binary.Msb

// Attrs is an ordinary map that represents a set of BGP path attributes.
// It should not contain nil values.
//
// Attrs and its values are not thread-safe.
type Attrs struct {
	db map[Code]Attr
}

// Init initializes Attrs. Can be called multiple times for lazy init.
func (ats *Attrs) Init() {
	if ats.db == nil {
		ats.db = map[Code]Attr{}
	}
}

// Valid returns true iff Attrs has already been initialized
func (ats *Attrs) Valid() bool {
	return ats.db != nil
}

// Reset resets Attrs back to initial state.
func (ats *Attrs) Reset() {
	ats.db = nil
}

// Clear drops all attributes.
func (ats *Attrs) Clear() {
	if ats.Valid() {
		clear(ats.db)
	}
}

// Len returns the number of attributes
func (ats *Attrs) Len() int {
	if ats.Valid() {
		return len(ats.db)
	} else {
		return 0
	}
}

// SetFrom sets all attributes from src, overwriting ats[ac] for existing attribute codes
func (ats *Attrs) SetFrom(src Attrs) {
	if !src.Valid() {
		return
	}

	ats.Init()
	for ac, at := range ats.db {
		ats.db[ac] = at
	}
}

// Get returns ats[ac] or nil if not possible.
func (ats *Attrs) Get(ac Code) Attr {
	if ats.Valid() {
		return ats.db[ac]
	} else {
		return nil
	}
}

// Has returns true iff ats[ac] is set and non-nil
func (ats *Attrs) Has(ac Code) bool {
	return ats.Get(ac) != nil
}

// Drop drops ats[ac].
func (ats *Attrs) Drop(ac Code) {
	if ats.Valid() {
		delete(ats.db, ac)
	}
}

// Set overwrites ats[ac] with value.
func (ats *Attrs) Set(ac Code, value Attr) {
	ats.Init()
	ats.db[ac] = value
}

// Use returns ats[ac] if its already set and non-nil.
// Otherwise, it adds a new instance for ac with default flags.
func (ats *Attrs) Use(ac Code) Attr {
	// already there?
	if ats.Valid() {
		if at, ok := ats.db[ac]; ok && at != nil {
			return at
		}
	} else {
		ats.Init()
	}

	// create, store, and return
	at := NewAttr(ac)
	ats.db[ac] = at
	return at
}

// Each executes cb for each attribute in ats,
// in an ascending order of attribute codes.
func (ats *Attrs) Each(cb func(i int, ac Code, at Attr)) {
	if !ats.Valid() {
		return
	}

	// dump ats into todo
	type attcode struct {
		ac Code
		at Attr
	}
	var todo []attcode
	for ac, at := range ats.db {
		if at != nil {
			todo = append(todo, attcode{ac, at})
		}
	}

	// sort todo
	sort.Slice(todo, func(i, j int) bool {
		return todo[i].ac < todo[j].ac
	})

	// run
	for i, c := range todo {
		cb(i, c.ac, c.at)
	}
}

func (ats *Attrs) MarshalJSON() ([]byte, error) {
	return ats.ToJSON(nil), nil
}

func (ats *Attrs) ToJSON(dst []byte) []byte {
	if !ats.Valid() {
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

// MP returns raw MP-BGP attribute ac
func (ats *Attrs) MP(ac Code) *MP {
	if a, ok := ats.Get(ac).(*MP); ok {
		return a
	}
	return nil
}

// MPPrefixes returns *MPPrefixes MP-BGP attribute ac
func (ats *Attrs) MPPrefixes(ac Code) *MPPrefixes {
	if a, ok := ats.Get(ac).(*MP); ok && a.Value != nil {
		pfx, _ := a.Value.(*MPPrefixes)
		return pfx
	}
	return nil
}

// Aspath returns the ATTR_ASPATH from u, or nil if not defined.
// TODO: support ATTR_AS4PATH
func (ats *Attrs) AsPath() *Aspath {
	if ap, ok := ats.Get(ATTR_ASPATH).(*Aspath); ok {
		return ap
	} else {
		return nil
	}
}

// AsOrigin returns the last AS in AS_PATH, or 0 on error
func (ats *Attrs) AsOrigin() uint32 {
	asp := ats.AsPath()
	if asp == nil {
		return 0
	}

	for i := len(asp.Segments) - 1; i >= 0; i-- {
		seg := &asp.Segments[i]
		switch {
		case len(seg.List) == 0:
			continue
		case seg.IsSet:
			return 0
		default:
			return seg.List[len(seg.List)-1]
		}
	}

	return 0
}
