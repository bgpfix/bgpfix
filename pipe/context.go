package pipe

import (
	"github.com/bgpfix/bgpfix/json"
	"github.com/bgpfix/bgpfix/msg"
)

// Context tracks message processing in a Pipe, stored in Msg.Value.
type Context struct {
	Pipe     *Pipe     // pipe processing the message
	Input    *Proc     // input processing the message (message source)
	Callback *Callback // currently running callback

	Action Action // requested message actions

	cbs  []*Callback       // callbacks scheduled to run
	tags map[string]string // simple Tag-Value store
}

// MsgContext returns message Context inside m, creating one if needed.
func MsgContext(m *msg.Msg) *Context {
	if mx, ok := m.Value.(*Context); ok {
		return mx
	} else {
		mx = new(Context)
		m.Value = mx
		return mx
	}
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
	clear(mx.tags)
}

// HasTag returns true iff the context has a Tag set
func (mx *Context) HasTag(tag string) bool {
	if mx.tags == nil {
		return false
	}
	_, ok := mx.tags[tag]
	return ok
}

// GetTag returns given Tag value, or "" if not set
func (mx *Context) GetTag(tag string) string {
	if mx.tags == nil {
		return ""
	}
	return mx.tags[tag]
}

// SetTag set given Tag to given value,
// or to a value of "" if not provided
func (mx *Context) SetTag(tag string, val ...string) {
	tags := mx.Tags()
	if len(val) > 0 {
		tags[tag] = val[0]
	} else {
		tags[tag] = ""
	}
}

// Tags returns a generic string Tag-Value store,
// creating it first if needed.
func (mx *Context) Tags() map[string]string {
	if mx.tags == nil {
		mx.tags = make(map[string]string)
	}
	return mx.tags
}

// TODO
func (mx *Context) ToJSON(dst []byte) []byte {
	return json.Byte(dst, byte(mx.Action))
}

// TODO
func (mx *Context) FromJSON(src []byte) error {
	val, err := json.UnByte(src)
	if err != nil {
		return err
	}
	mx.Action = Action(val)
	return nil
}
