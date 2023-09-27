package pipe

import (
	"github.com/bgpfix/bgpfix/json"
	"github.com/bgpfix/bgpfix/msg"
)

// PipeContext tracks message processing progress in a pipe
type PipeContext struct {
	Pipe *Pipe      // pipe processing the message
	Dir  *Direction // direction processing the message

	Callbacks []*Callback // callbacks to run
	Reverse   bool        // iterate over callbacks in reverse?
	Index     int         // minimum Callback.Index (maximum if Reverse is true)

	Callback *Callback // currently run callback
	Action   Action    // requested message actions

	kv map[string]any // generic Key-Value store
}

// Context returns pipe Context inside message m,
// updating m.Value if needed.
func Context(m *msg.Msg) *PipeContext {
	if m == nil {
		return nil
	} else if pc, ok := m.Value.(*PipeContext); ok {
		return pc
	} else {
		pc = new(PipeContext)
		m.Value = pc
		return pc
	}
}

// PipeAction returns pipe Action reference for given message m.
func PipeAction(m *msg.Msg) *Action {
	return &Context(m).Action
}

// Reset resets pc to empty state
func (pc *PipeContext) Reset() {
	*pc = PipeContext{}
}

// Clear resets pc, but preserves ACTION_BORROW if set.
func (pc *PipeContext) Clear() {
	a := pc.Action
	pc.Reset()
	pc.Action = a & ACTION_BORROW
}

// HasKV returns true iff the context already has a Key-Value store.
func (pc *PipeContext) HasKV() bool {
	return pc.kv != nil
}

// KV returns a generic Key-Value store, creating it first if needed.
func (pc *PipeContext) KV() map[string]any {
	if pc.kv == nil {
		pc.kv = make(map[string]interface{})
	}
	return pc.kv
}

// TODO
func (pc *PipeContext) ToJSON(dst []byte) []byte {
	return json.Byte(dst, byte(pc.Action))
}

// TODO
func (pc *PipeContext) FromJSON(src []byte) error {
	val, err := json.UnByte(src)
	if err != nil {
		return err
	}
	pc.Action = Action(val)
	return nil
}
