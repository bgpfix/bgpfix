package pipe

import (
	"strconv"
	"strings"

	"github.com/bgpfix/bgpfix/json"
	"github.com/bgpfix/bgpfix/msg"
)

// Action requests special handling of a message or event in a Pipe
type Action byte

// The default, zero action: keep processing as-is.
const ACTION_OK Action = 0

const (
	// Keep the message for later use, do not re-use its memory.
	//
	// You must use this if you wish to re-inject the message,
	// or keep reference to some value inside the msg.
	//
	// Once set, you must not remove this action from a message
	// unless you know you are the sole owner of this message.
	ACTION_BORROW Action = 1 << iota

	// Drop the message/event immediately (skip other calls, drop from output).
	//
	// If you want to re-inject the message later, set ACTION_BORROW too.
	// When re-injecting, clear the Action first, and remember the message will re-start
	// processing from the next callback, unless you clear its Context.
	ACTION_DROP

	// Accept the message/event immediately (skip other calls, proceed to output)
	ACTION_ACCEPT

	// Mask is logical OR of all defined actions
	ACTION_MASK Action = 1<<iota - 1
)

// Clear clears all bits except for ACTION_BORROW
func (ac *Action) Clear() {
	*ac &= ACTION_BORROW
}

// Add adds a to action ac
func (ac *Action) Add(a Action) {
	*ac |= a
}

// Has returns true iff a is set in ac
func (ac Action) Has(a Action) bool {
	return ac&a != 0
}

// HasBorrow returns true iff ACTION_BORROW is set in ac
func (ac Action) HasBorrow() bool {
	return ac&ACTION_BORROW != 0
}

// Borrow adds ACTION_BORROW
func (ac *Action) Borrow() {
	*ac |= ACTION_BORROW
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

// HasNot returns true iff a is NOT set in ac
func (ac Action) HasNot(a Action) bool {
	return ac&a == 0
}

// ActionClear clears all action flags but ACTION_BORROW in m and returns it.
func ActionClear(m *msg.Msg) *msg.Msg {
	if mx := GetContext(m); mx != nil {
		mx.Action.Clear()
	}
	return m
}

// ActionBorrow adds ACTION_BORROW to m and returns it.
func ActionBorrow(m *msg.Msg) *msg.Msg {
	UseContext(m).Action.Add(ACTION_BORROW)
	return m
}

// ActionHasBorrow returns true if ACTION_BORROW is set in m.
func ActionHasBorrow(m *msg.Msg) bool {
	if mx := GetContext(m); mx != nil {
		return mx.Action.Has(ACTION_BORROW)
	} else {
		return false
	}
}

// ActionDrop adds ACTION_DROP to m and returns it.
func ActionDrop(m *msg.Msg) *msg.Msg {
	UseContext(m).Action.Add(ACTION_DROP)
	return m
}

// ActionHasDrop returns true if ACTION_DROP is set in m.
func ActionHasDrop(m *msg.Msg) bool {
	if mx := GetContext(m); mx != nil {
		return mx.Action.Has(ACTION_DROP)
	} else {
		return false
	}
}

// ActionAccept adds ACTION_ACCEPT to m and returns it.
func ActionAccept(m *msg.Msg) *msg.Msg {
	UseContext(m).Action.Add(ACTION_ACCEPT)
	return m
}

// ActionHasAccept returns true if ACTION_ACCEPT is set in m.
func ActionHasAccept(m *msg.Msg) bool {
	if mx := GetContext(m); mx != nil {
		return mx.Action.Has(ACTION_ACCEPT)
	} else {
		return false
	}
}

// ToJSON appends JSON representation to dst
func (ac Action) ToJSON(dst []byte) []byte {
	if ac == 0 {
		return append(dst, '0')
	}

	dst = append(dst, '"')
	if ac&ACTION_BORROW != 0 {
		dst = append(dst, `BORROW|`...)
		ac &= ^ACTION_BORROW
	}
	if ac&ACTION_DROP != 0 {
		dst = append(dst, `DROP|`...)
		ac &= ^ACTION_DROP
	}
	if ac&ACTION_ACCEPT != 0 {
		dst = append(dst, `ACCEPT|`...)
		ac &= ^ACTION_ACCEPT
	}
	if ac != 0 {
		dst = append(json.Byte(dst, byte(ac)), '|')
	}
	dst[len(dst)-1] = '"'
	return dst

}

// FromJSON parses JSON representation in src
func (ac *Action) FromJSON(src []byte) error {
	ac.Clear()
	vs := strings.ToUpper(json.SQ(src))
	for _, v := range strings.Split(vs, "|") {
		switch v {
		case "", "0", "OK":
			continue // no-op
		case "BORROW":
			*ac |= ACTION_BORROW
		case "DROP":
			*ac |= ACTION_DROP
		case "ACCEPT":
			*ac |= ACTION_ACCEPT
		default:
			val, err := strconv.ParseUint(v, 0, 8)
			if err != nil {
				return err
			}
			*ac |= Action(val)
		}
	}
	return nil
}
