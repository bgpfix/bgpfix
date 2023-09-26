package pipe

import (
	"github.com/bgpfix/bgpfix/json"
	"github.com/bgpfix/bgpfix/msg"
)

// Context tracks message processing progress in a pipe
type Context struct {
	Dir       *Direction  // pipe direction processing the message
	Callback  *Callback   // currently run callback
	Callbacks []*Callback // callbacks to run (nil = from pipe Options)

	Action Action // requested message actions

	kv      map[string]interface{} // generic Key-Value store
	cbIndex int                    // minimum callback index
}

// PipeContext returns pipe Context inside message m,
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

// Clear resets pc, but preserves ACTION_BORROW if set.
func (pc *Context) Clear() {
	a := pc.Action
	pc.Reset()
	pc.Action = a & ACTION_BORROW
}

// SkipBefore requests to skip callbacks added to pipe.Options before cb.
func (pc *Context) SkipBefore(cb *Callback) {
	pc.cbIndex = cb.Index
}

// SkipAfter requests to skip callbacks added to pipe.Options before cb, plus cb itself.
func (pc *Context) SkipAfter(cb *Callback) {
	pc.cbIndex = cb.Index + 1
}

// HasKV returns true iff the context already has a Key-Value store.
func (pc *Context) HasKV() bool {
	return pc.kv != nil
}

// KV returns a generic Key-Value store, creating it first if needed.
func (pc *Context) KV() map[string]any {
	if pc.kv == nil {
		pc.kv = make(map[string]interface{})
	}
	return pc.kv
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
