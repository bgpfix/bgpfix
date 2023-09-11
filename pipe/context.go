package pipe

import (
	"github.com/bgpfix/bgpfix/json"
	"github.com/bgpfix/bgpfix/msg"
)

// Context tracks message processing progress in a pipe
type Context struct {
	Pipe      *Pipe      // pipe processing the message
	Direction *Direction // pipe direction
	Callback  *Callback  // the current callback
	Action    Action     // actions requested so far
}

// PipeContext returns pipe Context for given message m,
// updating m.Value if needed.
func PipeContext(m *msg.Msg) *Context {
	if m == nil {
		return nil
	} else if pc, ok := m.Value.(*Context); ok {
		return pc
	} else {
		pc = new(Context)
		m.Value = pc
		return pc
	}
}

// PipeAction returns pipe Action reference for given message m.
func PipeAction(m *msg.Msg) *Action {
	return &PipeContext(m).Action
}

// Reset resets pc to empty state
func (pc *Context) Reset() {
	*pc = Context{}
}

// Clear is like Reset but preserves ACTION_BORROW if set.
func (pc *Context) Clear() {
	pc.Action.Clear()
	action := pc.Action
	pc.Reset()
	pc.Action = action
}

// TODO
func (pc *Context) ToJSON(dst []byte) []byte {
	return json.Byte(dst, byte(pc.Action))
}

// TODO
func (pc *Context) FromJSON(src []byte) error {
	val, err := json.UnByte(src)
	if err != nil {
		return err
	}
	pc.Action = Action(val)
	return nil
}
