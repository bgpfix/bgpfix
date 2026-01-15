// Package caps implements BGP capabilities.
//
// This package can store a set of BGP capabilities in a thread-safe map
// using the Caps type, and read/write a particular BGP capability
// representation using implementations of the Cap interface.
package caps

import (
	"fmt"
	"sort"

	"github.com/bgpfix/bgpfix/binary"
	"github.com/bgpfix/bgpfix/json"
	"github.com/puzpuzpuz/xsync/v4"
)

var msb = binary.Msb

// Caps wraps an xsync map to represent a set of BGP capabilities.
// It may contain nil values.
//
// Caps is thread-safe for writes, but only after Init() or first modification.
//
// The Cap values stored in Caps are generally *not* thread-safe for writes,
// so you should overwrite a particular CapCode if you need to modify a Cap
// stored here in a thread-safe way.
type Caps struct {
	// the database of capabilities, initially nil
	db *xsync.Map[Code, Cap]
}

// Init initializes Caps and makes it fully thread-safe after return.
// Can be called multiple times for lazy init.
func (cps *Caps) Init() {
	if cps.db == nil {
		cps.db = xsync.NewMap[Code, Cap]()
	}
}

// Valid returns true iff Caps has already been initialized
func (cps *Caps) Valid() bool {
	return cps.db != nil
}

// Reset resets Caps back to initial state. Thread-unsafe.
func (cps *Caps) Reset() {
	cps.db = nil
}

// Clear drops all capabilities.
func (cps *Caps) Clear() {
	if cps.Valid() {
		cps.db.Clear()
	}
}

// Len returns the number of capabilites
func (cps *Caps) Len() int {
	if cps.Valid() {
		return cps.db.Size()
	} else {
		return 0
	}
}

// SetFrom sets all capabilities from src, overwriting cps[cc] for existing capability codes
func (cps *Caps) SetFrom(src Caps) {
	if !src.Valid() {
		return
	}

	cps.Init()
	for cc, cap := range src.db.All() {
		cps.db.Store(cc, cap)
	}
}

// Get returns cps[cc] or nil if not possible.
func (cps *Caps) Get(cc Code) (cap Cap) {
	if cps.Valid() {
		cap, _ = cps.db.Load(cc)
	}
	return
}

// Has returns true iff cps[cc] is set and non-nil
func (cps *Caps) Has(cc Code) bool {
	return cps.Get(cc) != nil
}

// Drop drops cps[cc].
func (cps *Caps) Drop(cc Code) {
	if cps.Valid() {
		cps.db.Delete(cc)
	}
}

// Set overwrites cps[cc] with value.
func (cps *Caps) Set(cc Code, value Cap) {
	cps.Init()
	cps.db.Store(cc, value)
}

// Use returns cps[cc] if its already there (may be nil).
// Otherwise, it adds a new instance of cc in cps.
func (cps *Caps) Use(cc Code) Cap {
	// already there?
	if cps.Valid() {
		if cap, ok := cps.db.Load(cc); ok {
			return cap
		}
	} else {
		cps.Init()
	}

	// create a new instance, store, return the winner
	cap := NewCap(cc)
	cap, _ = cps.db.LoadOrStore(cc, cap)
	return cap
}

// Each executes cb for each non-nil capability in cps,
// in an ascending order of capability codes.
func (cps *Caps) Each(cb func(i int, cc Code, cap Cap)) {
	if !cps.Valid() {
		return
	}

	// dump cps into todo
	type capcode struct {
		cc  Code
		cap Cap
	}
	var todo []capcode
	for cc, cap := range cps.db.All() {
		if cap != nil {
			todo = append(todo, capcode{cc, cap})
		}
	}

	// sort todo
	sort.Slice(todo, func(i, j int) bool {
		return todo[i].cc < todo[j].cc
	})

	// run
	for i, c := range todo {
		cb(i, c.cc, c.cap)
	}
}

func (cps *Caps) String() string {
	return string(cps.ToJSON(nil))
}

func (cps *Caps) MarshalJSON() (dst []byte, err error) {
	return cps.ToJSON(nil), nil
}

func (cps *Caps) ToJSON(dst []byte) []byte {
	if !cps.Valid() {
		return append(dst, "null"...)
	}

	dst = append(dst, '{')
	cps.Each(func(i int, cc Code, cap Cap) {
		if i > 0 {
			dst = append(dst, ',')
		}
		dst = cc.ToJSON(dst)
		dst = append(dst, ':')
		dst = cap.ToJSON(dst)
	})
	return append(dst, '}')
}

func (cps *Caps) FromJSON(src []byte) error {
	return json.ObjectEach(src, func(key string, val []byte, typ json.Type) error {
		// is key a valid capability code?
		var cc Code
		if err := cc.FromJSON(key); err != nil {
			return fmt.Errorf("%w: %w", ErrCapCode, err)
		}
		c := cps.Use(cc)

		// parse?
		if err := c.FromJSON(val); err != nil {
			return err
		}

		// success!
		return nil
	})
}
