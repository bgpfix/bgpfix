package pipe

import "github.com/bgpfix/bgpfix/msg"

// Action requests special handling of a message or event in a Pipe
type Action byte

const (
	// The default, zero action: keep processing as-is.
	ACTION_OK Action = 0

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
	// If you want to re-inject a message later, set ACTION_BORROW too,
	// and keep in mind the message will try to re-start after where
	// you dropped it, unless you call Context.Clear on it.
	ACTION_DROP

	// Accept the message/event immediately (skip other calls, proceed to output)
	ACTION_ACCEPT
)

// Clear clears all bits except for ACTION_BORROW
func (ac *Action) Clear() {
	*ac &= ACTION_BORROW
}

// Add adds a to action ac
func (ac *Action) Add(a Action) {
	*ac |= a
}

// Is returns true iff a is set in ac
func (ac Action) Is(a Action) bool {
	return ac&a != 0
}

// IsBorrow returns true iff ACTION_BORROW is set in ac
func (ac Action) IsBorrow() bool {
	return ac&ACTION_BORROW != 0
}

// Borrow adds ACTION_BORROW
func (ac *Action) Borrow() {
	*ac |= ACTION_BORROW
}

// IsAccept returns true iff ACTION_ACCEPT is set in ac
func (ac Action) IsAccept() bool {
	return ac&ACTION_ACCEPT != 0
}

// Accept adds ACTION_ACCEPT
func (ac *Action) Accept() {
	*ac |= ACTION_ACCEPT
}

// IsDrop returns true iff ACTION_DROP is set in ac
func (ac Action) IsDrop() bool {
	return ac&ACTION_DROP != 0
}

// Drop adds ACTION_DROP
func (ac *Action) Drop() {
	*ac |= ACTION_DROP
}

// IsNot returns true iff a is NOT set in ac
func (ac Action) Not(a Action) bool {
	return ac&a == 0
}

// ActionClear clears all action flags but ACTION_BORROW in m and returns it.
func ActionClear(m *msg.Msg) *msg.Msg {
	MsgContext(m).Action.Clear()
	return m
}

// ActionBorrow adds ACTION_BORROW to m and returns it.
func ActionBorrow(m *msg.Msg) *msg.Msg {
	MsgContext(m).Action.Add(ACTION_BORROW)
	return m
}

// ActionIsBorrow returns true if ACTION_BORROW is set in m.
func ActionIsBorrow(m *msg.Msg) bool {
	return MsgContext(m).Action.Is(ACTION_BORROW)
}

// ActionDrop adds ACTION_DROP to m and returns it.
func ActionDrop(m *msg.Msg) *msg.Msg {
	MsgContext(m).Action.Add(ACTION_DROP)
	return m
}

// ActionIsDrop returns true if ACTION_DROP is set in m.
func ActionIsDrop(m *msg.Msg) bool {
	return MsgContext(m).Action.Is(ACTION_DROP)
}

// ActionAccept adds ACTION_ACCEPT to m and returns it.
func ActionAccept(m *msg.Msg) *msg.Msg {
	MsgContext(m).Action.Add(ACTION_ACCEPT)
	return m
}

// ActionIsAccept returns true if ACTION_ACCEPT is set in m.
func ActionIsAccept(m *msg.Msg) bool {
	return MsgContext(m).Action.Is(ACTION_ACCEPT)
}
