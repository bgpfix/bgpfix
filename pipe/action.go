package pipe

import (
	"strconv"
	"strings"

	"github.com/bgpfix/bgpfix/json"
)

// Action requests special handling of a message or event in a Pipe
type Action byte

// The default, zero action: keep processing as-is.
const ACTION_OK Action = 0

const (
	// A reference to the message, or to a value inside it, is kept:
	// never re-use its memory. Once set, never remove it.
	ACTION_REF Action = 1 << iota

	// Drop the message/event immediately (skip other calls, drop from output).
	ACTION_DROP

	// Accept the message/event immediately (skip other calls, proceed to output)
	ACTION_ACCEPT

	// The message was taken by a callback, see Take()
	ACTION_TAKE

	// Mask is logical OR of all defined actions
	ACTION_MASK Action = 1<<iota - 1
)

// Add adds a to action ac
func (ac *Action) Add(a Action) {
	*ac |= a
}

// Has returns true iff a is set in ac
func (ac Action) Has(a Action) bool {
	return ac&a != 0
}

// HasAccept returns true iff ACTION_ACCEPT is set in ac
func (ac Action) HasAccept() bool {
	return ac&ACTION_ACCEPT != 0
}

// Accept adds ACTION_ACCEPT
func (ac *Action) Accept() {
	*ac |= ACTION_ACCEPT
}

// HasDrop returns true iff ACTION_DROP is set in ac
func (ac Action) HasDrop() bool {
	return ac&ACTION_DROP != 0
}

// Drop adds ACTION_DROP
func (ac *Action) Drop() {
	*ac |= ACTION_DROP
}

var actionNames = []struct {
	a    Action
	name string
}{{ACTION_REF, "REF"}, {ACTION_DROP, "DROP"}, {ACTION_ACCEPT, "ACCEPT"}, {ACTION_TAKE, "TAKE"}}

// ToJSON appends JSON representation to dst
func (ac Action) ToJSON(dst []byte) []byte {
	if ac == 0 {
		return append(dst, '0')
	}

	dst = append(dst, '"')
	for _, an := range actionNames {
		if ac&an.a != 0 {
			dst = append(append(dst, an.name...), '|')
			ac &^= an.a
		}
	}
	if ac != 0 {
		dst = append(json.Byte(dst, byte(ac)), '|')
	}
	dst[len(dst)-1] = '"'
	return dst
}

// FromJSON parses JSON representation in src
func (ac *Action) FromJSON(src []byte) error {
	*ac = 0
next:
	for _, v := range strings.Split(strings.ToUpper(json.SQ(src)), "|") {
		if v == "" || v == "0" || v == "OK" {
			continue
		}
		for _, an := range actionNames {
			if v == an.name {
				*ac |= an.a
				continue next
			}
		}
		val, err := strconv.ParseUint(v, 0, 8)
		if err != nil {
			return err
		}
		*ac |= Action(val)
	}
	return nil
}
