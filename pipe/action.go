package pipe

// Action corresponds to m.Action values
type Action byte

const (
	// The default, zero action: keep processing as-is.
	ACTION_CONTINUE Action = 0

	// Keep the message for later use, do not re-use its memory.
	//
	// You must use this if you wish to re-inject the message,
	// or keep reference to some value inside the msg.
	//
	// Once set, you must not remove this action from a message
	// unless you know you are the sole owner of this message.
	ACTION_BORROW Action = 1 << iota

	// Drop the message immediately from the pipe.
	//
	// If you want to re-inject the message later, set ACTION_BORROW
	// and keep in mind the message will try to re-start where
	// you dropped it, unless you set Context.Callback to nil.
	ACTION_DROP

	// Accept the message immediately and write to pipe output.
	ACTION_ACCEPT
)

// Clear clears all bits except for BORROW
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

// IsNot returns true iff a is NOT set in ac
func (ac Action) Not(a Action) bool {
	return ac&a == 0
}
