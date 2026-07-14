// Package meta represents BGP message parsing context.
//
// Exported to a separate package in order to avoid dependency loops:
// message parsers take *Meta, which is part of msg.Msg.
package meta

import (
	"strconv"

	"github.com/bgpfix/bgpfix/json"
)

// Meta holds BGP message parsing context: the message direction, plus
// optional per-message overrides of session capabilities that affect
// how the message data is parsed.
//
// NB: Meta pertains to parsing only - it must not affect marshaling.
// NB: a nil *Meta is valid and means "no parsing context available".
type Meta struct {
	Dir Dir // message direction

	// per-message parse overrides of session capabilities,
	// eg. for MRT files that mix AS2 and AS4 messages
	ParseAS4     Tri // 4-byte ASN encoding (CAP_AS4)
	ParseAddPath Tri // ADD-PATH encoding (CAP_ADDPATH)
}

// Direction returns the message direction, or 0 if m is nil
func (m *Meta) Direction() Dir {
	if m == nil {
		return 0
	}
	return m.Dir
}

// HasAS4 returns the ParseAS4 override in m, or the session default sess if not set
func (m *Meta) HasAS4(sess bool) bool {
	if m == nil {
		return sess
	}
	return m.ParseAS4.Or(sess)
}

// HasAddPath returns the ParseAddPath override in m, or the session default sess if not set
func (m *Meta) HasAddPath(sess bool) bool {
	if m == nil {
		return sess
	}
	return m.ParseAddPath.Or(sess)
}

// Defined returns true iff m contains any parse overrides
func (m *Meta) Defined() bool {
	return m != nil && (m.ParseAS4 != TRI_UNSET || m.ParseAddPath != TRI_UNSET)
}

// ToJSON appends JSON representation of the parse overrides to dst
func (m *Meta) ToJSON(dst []byte) []byte {
	dst = append(dst, '{')
	if m.ParseAS4 != TRI_UNSET {
		dst = append(dst, `"AS4":`...)
		dst = strconv.AppendBool(dst, m.ParseAS4 == TRI_ON)
	}
	if m.ParseAddPath != TRI_UNSET {
		if dst[len(dst)-1] != '{' {
			dst = append(dst, ',')
		}
		dst = append(dst, `"ADDPATH":`...)
		dst = strconv.AppendBool(dst, m.ParseAddPath == TRI_ON)
	}
	return append(dst, '}')
}

// FromJSON reads parse overrides from JSON object in src
func (m *Meta) FromJSON(src []byte) error {
	return json.ObjectEach(src, func(key string, val []byte, typ json.Type) error {
		switch key {
		case "AS4":
			m.ParseAS4 = TriBool(json.S(val) == "true")
		case "ADDPATH":
			m.ParseAddPath = TriBool(json.S(val) == "true")
		}
		return nil
	})
}

// Tri is a tri-state flag: unset, on, or off
type Tri byte

const (
	TRI_UNSET Tri = 0
	TRI_ON    Tri = 1
	TRI_OFF   Tri = 2
)

// TriBool converts bool to Tri
func TriBool(b bool) Tri {
	if b {
		return TRI_ON
	}
	return TRI_OFF
}

// Or returns the value of t, or the fallback if t is not set
func (t Tri) Or(fallback bool) bool {
	if t == TRI_UNSET {
		return fallback
	}
	return t == TRI_ON
}
