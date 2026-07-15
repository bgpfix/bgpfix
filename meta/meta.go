// Package meta represents BGP message metadata.
//
// Exported to a separate package in order to avoid dependency loops:
// message parsers take *Meta, which is part of msg.Msg.
package meta

import "time"

// Meta holds optional BGP message metadata: the direction, sequence number
// and timestamp, plus per-message parser options.
//
// NB: a nil *Meta is valid and means "no metadata available".
type Meta struct {
	Dir  Dir       // message direction
	Seq  int64     // sequence number
	Time time.Time // message timestamp

	// per-message parser options, overriding session capabilities,
	// eg. for MRT files that mix AS2 and AS4 messages:
	// 0 = no data, -1 = disabled, 1 = enabled
	//
	// NB: an internal signal controlling the parsers - it must never
	// affect marshaling, and is not written to (or read from) JSON

	ParseAS4     int8 // 4-byte ASN encoding (CAP_AS4)
	ParseAddPath int8 // ADD-PATH encoding (CAP_ADDPATH)
}

// Direction returns the message direction, or 0 if mt is nil
func (mt *Meta) Direction() Dir {
	if mt == nil {
		return 0
	}
	return mt.Dir
}

// HasAS4 returns the ParseAS4 option in mt, or the session default sess if no data
func (mt *Meta) HasAS4(sess bool) bool {
	if mt == nil || mt.ParseAS4 == 0 {
		return sess
	}
	return mt.ParseAS4 > 0
}

// HasAddPath returns the ParseAddPath option in mt, or the session default sess if no data
func (mt *Meta) HasAddPath(sess bool) bool {
	if mt == nil || mt.ParseAddPath == 0 {
		return sess
	}
	return mt.ParseAddPath > 0
}
