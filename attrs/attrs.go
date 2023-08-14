// Package attrs represents BGP path attributes.
//
// This package can store a set of BGP attributes in a thread-unsafe map
// using the Attrs type, and read/write a particular BGP attribute
// representation using implementations of the Attr interface.
package attrs

import (
	"fmt"
	"sort"

	jsp "github.com/buger/jsonparser"
)

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
		return append(dst, "null"...)
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
	mkerr := func(key []byte, err error) error {
		return fmt.Errorf("attrs[%s]: %w", key, err)
	}

	return jsp.ObjectEach(src, func(key, val []byte, _ jsp.ValueType, _ int) error {
		// is key a valid attribute code?
		var acode Code
		if acode.FromJSON(key) != nil {
			return mkerr(key, ErrAttrCode)
		}
		attr := ats.Use(acode)

		// fetch the value and flags
		fval, _, _, ferr := jsp.Get(val, "flags")
		vval, _, _, verr := jsp.Get(val, "value")

		// has flags?
		if ferr == nil {
			var af Flags
			if af.FromJSON(fval) != nil {
				return mkerr(key, ErrAttrFlags)
			}
			attr.SetFlags(af)
		} else { // use default flags, try to use whole buf as vval
			vval = val
			verr = nil
		}

		// has the value?
		if verr != nil || len(vval) == 0 {
			return mkerr(key, ErrValue)
		}

		// parse
		if err := attr.FromJSON(vval); err != nil {
			return mkerr(key, err)
		}
		return nil
	})
}
