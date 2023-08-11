package pipe

import "github.com/bgpfix/bgpfix/msg"

// Action corresponds to m.Action values
type Action = byte

const (
	ACTION_DROP Action = 1 << iota // stop processing immediately

	ACTION_KEEP  // do not return the message to pool
	ACTION_FINAL // skip more callbacks, proceed to output now
)

// ActionIs returns true iff ca is set in m.Action
func ActionIs(m *msg.Msg, ca Action) bool {
	return m.Action&byte(ca) != 0
}

// ActionNot returns true iff ca is NOT set in m.Action
func ActionNot(m *msg.Msg, ca Action) bool {
	return m.Action&byte(ca) == 0
}
