// Package meta represents BGP message metadata.
//
// Exported to a separate package in order to avoid dependency loops:
// message parsers take Meta, which is part of msg.Msg.
package meta

import (
	"slices"
	"time"

	"github.com/bgpfix/bgpfix/afi"
)

// Meta holds optional BGP message metadata: the direction, sequence number
// and timestamp, plus per-message parser options.
//
// NB: passed by value to parsers; the zero value means "no metadata".
type Meta struct {
	Dir  Dir       // message direction
	Seq  int64     // sequence number
	Time time.Time // message timestamp

	// per-message parser options, overriding session capabilities
	ParseAS4     int8     // 4-byte ASN encoding (CAP_AS4): 0 = no data, -1 = off, 1 = on
	ParseAddPath *AddPath // ADD-PATH encoding (CAP_ADDPATH): nil = no data
}

// AddPath tells which address families carry ADD-PATH Path Identifiers (RFC 7911).
// NB: shared and read-only, eg. AddPathOn and AddPathOff
type AddPath struct {
	All bool     // all address families
	AS  []afi.AS // else only these
}

var (
	AddPathOn  = &AddPath{All: true} // ADD-PATH in all address families
	AddPathOff = &AddPath{}          // no ADD-PATH
)

// Has returns true iff ap enables ADD-PATH for address family as
func (ap *AddPath) Has(as afi.AS) bool {
	return ap.All || slices.Contains(ap.AS, as)
}

// Reset resets the metadata to its zero value.
func (mt *Meta) Reset() {
	if mt != nil {
		*mt = Meta{}
	}
}
