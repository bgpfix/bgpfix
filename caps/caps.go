// Package caps represents BGP capabilities.
//
// This package can store a set of BGP capabilities in a thread-safe map
// using the Caps type, and read/write a particular BGP capability
// representation using implementations of the Cap interface.
package caps

import (
	"sort"

	"github.com/bgpfix/bgpfix/binary"
	"github.com/puzpuzpuz/xsync/v2"
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
	db *xsync.MapOf[Code, Cap]
}

// Init initializes Caps and makes it fully thread-safe after return.
// Can be called multiple times for lazy init.
func (caps *Caps) Init() {
	if caps.db == nil {
		caps.db = xsync.NewIntegerMapOf[Code, Cap]()
	}
}

// Valid returns true iff Caps has already been initialized
func (caps *Caps) Valid() bool {
	return caps.db != nil
}

// Reset resets Caps back to initial state. Thread-unsafe.
func (caps *Caps) Reset() {
	caps.db = nil
}

// Clear drops all capabilities.
func (caps *Caps) Clear() {
	if caps.Valid() {
		caps.db.Clear()
	}
}

// Len returns the number of capabilites
func (caps *Caps) Len() int {
	if caps.Valid() {
		return caps.db.Size()
	} else {
		return 0
	}
}

// SetFrom sets all capabilities from src, overwriting caps[cc] for existing capability codes
func (caps *Caps) SetFrom(src Caps) {
	if !src.Valid() {
		return
	}

	caps.Init()
	src.db.Range(func(cc Code, cap Cap) bool {
		caps.db.Store(cc, cap)
		return true
	})
}

// Get returns caps[cc] or nil if not possible.
func (caps *Caps) Get(cc Code) (cap Cap) {
	if caps.Valid() {
		cap, _ = caps.db.Load(cc)
	}
	return
}

// Has returns true iff caps[cc] is set and non-nil
func (caps *Caps) Has(cc Code) bool {
	return caps.Get(cc) != nil
}

// Drop drops caps[cc].
func (caps *Caps) Drop(cc Code) {
	if caps.Valid() {
		caps.db.Delete(cc)
	}
}

// Set overwrites caps[cc] with value.
func (caps *Caps) Set(cc Code, value Cap) {
	caps.Init()
	caps.db.Store(cc, value)
}

// Use returns caps[cc] if its already there (may be nil).
// Otherwise, it adds a new instance of cc in caps.
func (caps *Caps) Use(cc Code) Cap {
	// already there?
	if caps.Valid() {
		if cap, ok := caps.db.Load(cc); ok {
			return cap
		}
	} else {
		caps.Init()
	}

	// create a new instance, store, return the winner
	cap := NewCap(cc)
	cap, _ = caps.db.LoadOrStore(cc, cap)
	return cap
}

// Each executes cb for each non-nil capability in caps,
// in an ascending order of capability codes.
func (caps *Caps) Each(cb func(i int, cc Code, cap Cap)) {
	if !caps.Valid() {
		return
	}

	// dump caps into todo
	type capcode struct {
		cc  Code
		cap Cap
	}
	var todo []capcode
	caps.db.Range(func(cc Code, cap Cap) bool {
		if cap != nil {
			todo = append(todo, capcode{cc, cap})
		}
		return true
	})

	// sort todo
	sort.Slice(todo, func(i, j int) bool {
		return todo[i].cc < todo[j].cc
	})

	// run
	for i, c := range todo {
		cb(i, c.cc, c.cap)
	}
}

func (caps *Caps) MarshalJSON() (dst []byte, err error) {
	return caps.ToJSON(nil), nil
}

func (caps *Caps) ToJSON(dst []byte) []byte {
	if !caps.Valid() {
		return append(dst, "null"...)
	}

	dst = append(dst, '{')
	caps.Each(func(i int, cc Code, cap Cap) {
		if i > 0 {
			dst = append(dst, `,"`...)
		} else {
			dst = append(dst, `"`...)
		}
		dst = append(dst, cc.String()...)
		dst = append(dst, `":`...)
		dst = cap.ToJSON(dst)
	})
	return append(dst, '}')
}
