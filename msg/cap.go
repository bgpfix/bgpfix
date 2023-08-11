package msg

import (
	"sort"

	"github.com/puzpuzpuz/xsync/v2"
)

// Cap represents a particular BGP capability
type Cap interface {
	// Common returns a new instance of the same capability that
	// represents its intersection with cap2.
	//
	// May return nil, eg. if cap and cap2 are equal.
	Common(cap2 Cap) Cap

	// Unmarshal parses wire representation from src.
	// It must support multiple calls for the same message.
	Unmarshal(src []byte, caps Caps) error

	// Marshal appends wire representation to dst, including code and length
	Marshal(dst []byte) []byte

	// ToJSON appends JSON representation of the value to dst
	ToJSON(dst []byte) []byte
}

// CapCode represents BGP capability code
type CapCode byte

// capability codes
//
//go:generate go run github.com/dmarkham/enumer -type=CapCode -trimprefix CAP_
const (
	CAP_UNSPECIFIED            CapCode = 0
	CAP_MP                     CapCode = 1
	CAP_ROUTE_REFRESH          CapCode = 2
	CAP_OUTBOUND_FILTERING     CapCode = 3
	CAP_EXTENDED_NEXTHOP       CapCode = 5
	CAP_EXTENDED_MESSAGE       CapCode = 6
	CAP_BGPSEC                 CapCode = 7
	CAP_MULTIPLE_LABELS        CapCode = 8
	CAP_ROLE                   CapCode = 9
	CAP_GRACEFUL_RESTART       CapCode = 64
	CAP_AS4                    CapCode = 65
	CAP_DYNAMIC                CapCode = 67
	CAP_MULTISESSION           CapCode = 68
	CAP_ADDPATH                CapCode = 69
	CAP_ENHANCED_ROUTE_REFRESH CapCode = 70
	CAP_LLGR                   CapCode = 71
	CAP_ROUTING_POLICY         CapCode = 72
	CAP_FQDN                   CapCode = 73
	CAP_BFD                    CapCode = 74
	CAP_VERSION                CapCode = 75
	CAP_PRE_ROUTE_REFRESH      CapCode = 128
)

// CapNewFunc returns a new instance of capability cc.
type CapNewFunc func(cc CapCode) Cap

// CapNew maps capability codes to their new func
var CapNew = map[CapCode]CapNewFunc{
	CAP_MP:               NewCapMP,
	CAP_AS4:              NewCapAS4,
	CAP_EXTENDED_NEXTHOP: NewCapExtNH,
}

// Code returns capability code
func (cc CapCode) Code() CapCode {
	return cc
}

// Caps represent a set of BGP capabilities. May contain nil values (meaning "ban").
//
// Caps is always safe for read access with no concurrent writes at the same time.
// For full thread-safety, modify it or call Init() first.
//
// Note the actual values returned from Caps are not thread-safe for concurrent write.
type Caps struct {
	db *xsync.MapOf[CapCode, Cap]
}

// Init initializes Caps and makes it fully thread-safe after return.
// Can be called multiple times for lazy init.
func (caps *Caps) Init() {
	if caps.db == nil {
		caps.db = xsync.NewIntegerMapOf[CapCode, Cap]()
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
	src.db.Range(func(cc CapCode, cap Cap) bool {
		caps.db.Store(cc, cap)
		return true
	})
}

// Get returns caps[cc] or nil if not possible.
func (caps *Caps) Get(cc CapCode) (cap Cap) {
	if caps.Valid() {
		cap, _ = caps.db.Load(cc)
	}
	return
}

// Has returns true iff caps[cc] is set and non-nil
func (caps *Caps) Has(cc CapCode) bool {
	return caps.Get(cc) != nil
}

// Drop drops caps[cc].
func (caps *Caps) Drop(cc CapCode) {
	if caps.Valid() {
		caps.db.Delete(cc)
	}
}

// Set overwrites caps[cc] with value.
func (caps *Caps) Set(cc CapCode, value Cap) {
	caps.Init()
	caps.db.Store(cc, value)
}

// Use returns caps[cc] if its already there (may be nil).
// Otherwise, it adds a new instance of cc in caps.
func (caps *Caps) Use(cc CapCode) Cap {
	// already there?
	if caps.Valid() {
		if cap, ok := caps.db.Load(cc); ok {
			return cap
		}
	} else {
		caps.Init()
	}

	// select the new func, default to raw
	newfunc, ok := CapNew[cc]
	if !ok {
		newfunc = NewCapRaw
	}

	// create a new instance, store, return the winner
	cap := newfunc(cc)
	cap, _ = caps.db.LoadOrStore(cc, cap)
	return cap
}

// Each executes cb for each capability in caps,
// in an ascending order of capability codes.
func (caps *Caps) Each(cb func(i int, cc CapCode, cap Cap)) {
	if !caps.Valid() {
		return
	}

	// dump caps into todo
	type capcode struct {
		cc  CapCode
		cap Cap
	}
	var todo []capcode
	caps.db.Range(func(cc CapCode, cap Cap) bool {
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
	caps.Each(func(i int, cc CapCode, cap Cap) {
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
