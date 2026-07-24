// Package meta represents BGP message metadata.
//
// Exported to a separate package in order to avoid dependency loops:
// message parsers take Meta, which is part of msg.Msg.
package meta

import "time"

// Meta holds optional BGP message metadata: the direction, sequence number
// and timestamp, plus per-message parser options.
//
// NB: passed by value to parsers; the zero value means "no metadata".
type Meta struct {
	Dir  Dir       // message direction
	Seq  int64     // sequence number
	Time time.Time // message timestamp

	// per-message parser options, overriding session capabilities:
	// 0 = no data, -1 = disabled, 1 = enabled
	ParseAS4     int8 // 4-byte ASN encoding (CAP_AS4)
	ParseAddPath int8 // ADD-PATH encoding (CAP_ADDPATH)
}
