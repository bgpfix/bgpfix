package pipe

import (
	"github.com/bgpfix/bgpfix/msg"
)

// Context tracks message processing in a Pipe, stored in Msg.Value.
type Context struct {
	Pipe     *Pipe       // pipe processing the message
	Input    *Input      // input processing the message (message source)
	Callback *Callback   // currently running callback
	cbs      []*Callback // all callbacks scheduled to run
	Action   Action      // requested message actions
}

// UseContext returns message Context inside m, creating one if needed.
func UseContext(m *msg.Msg) *Context {
	if mx, ok := m.Value.(*Context); ok {
		return mx
	} else {
		mx = new(Context)
		m.Value = mx
		return mx
	}
}

// GetContext returns message Context inside m, iff it exists (or nil).
func GetContext(m *msg.Msg) *Context {
	mx, _ := m.Value.(*Context)
	return mx
}

// Take takes m from the pipe: when the callback returns, the pipe forgets m, and
// you own it. Eg. hold it and send it later with Input.WriteMsg, which processes
// it as new, or drop it with Pipe.PutMsg. Call only from the callback of m.
func Take(m *msg.Msg) {
	mx := UseContext(m)
	mx.Action |= ACTION_TAKE
	mx.Input.taken = true
}

// Reset resets pc to empty state
func (mx *Context) Reset() {
	if mx == nil {
		return
	}

	mx.Pipe = nil
	mx.Input = nil
	mx.Callback = nil
	mx.Action = 0
	mx.cbs = nil // NB: do not [:0] and re-use
}
