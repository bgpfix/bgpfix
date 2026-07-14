// Package meta represents optional BGP message metadata.
//
// Exported to a separate package in order to avoid dependency loops:
// message marshal/unmarshal code takes *Meta, which is part of msg.Msg.
package meta

import "time"

// Meta holds optional BGP message metadata, including per-message
// overrides of session capabilities that affect the wire format.
//
// NB: a nil *Meta is valid and means "no metadata available".
type Meta struct {
	Dir  Dir       // message direction
	Seq  int64     // sequence number
	Time time.Time // message timestamp

	// per-message overrides of session capabilities,
	// eg. for MRT files that mix AS2 and AS4 messages
	AS4     Tri // 4-byte ASN encoding (CAP_AS4)
	AddPath Tri // ADD-PATH encoding (CAP_ADDPATH)
}

// Direction returns the message direction, or 0 if m is nil
func (m *Meta) Direction() Dir {
	if m == nil {
		return 0
	}
	return m.Dir
}

// HasAS4 returns the AS4 override in m, or the session default sess if not set
func (m *Meta) HasAS4(sess bool) bool {
	if m == nil {
		return sess
	}
	return m.AS4.Or(sess)
}

// HasAddPath returns the ADD-PATH override in m, or the session default sess if not set
func (m *Meta) HasAddPath(sess bool) bool {
	if m == nil {
		return sess
	}
	return m.AddPath.Or(sess)
}

// Tri is a tri-state flag: unset, on, or off
type Tri byte

const (
	TRI_UNSET Tri = 0
	TRI_ON    Tri = 1
	TRI_OFF   Tri = 2
)

// Or returns the value of t, or the fallback if t is not set
func (t Tri) Or(fallback bool) bool {
	if t == TRI_UNSET {
		return fallback
	}
	return t == TRI_ON
}
