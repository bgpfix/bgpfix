package pipe

import (
	"github.com/bgpfix/bgpfix/json"
	"github.com/bgpfix/bgpfix/msg"
)

// PipeContext tracks message processing progress in a pipe
type PipeContext struct {
	Pipe *Pipe      // pipe processing the message
	Dir  *Direction // direction processing the message

	// The Callback.Id to start processing scheduled callbacks at.
	// Allows for injecting messages at arbitrary pipe location.
	// If >0, this is the minimum Id value (or the maximum in reverse mode)
	// to run a callback. If 0, the filter is disabled.
	StartAt int

	Callback *Callback // currently run callback
	Action   Action    // requested message actions

	cbs []*Callback    // scheduled callbacks to run
	kv  map[string]any // generic Key-Value store
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

// NoCallbacks requests the message to skip running any callbacks
func (pc *PipeContext) NoCallbacks() {
	pc.cbs = noCallbacks
}

var noCallbacks = []*Callback{}

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
