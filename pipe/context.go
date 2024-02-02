package pipe

import (
	"github.com/bgpfix/bgpfix/json"
	"github.com/bgpfix/bgpfix/msg"
)

// Context tracks message processing progress in a pipe,
// and is usually stored in Msg.Value.
type Context struct {
	Pipe     *Pipe     // pipe processing the message
	Input    *Input    // input processing the message (message source)
	Callback *Callback // currently running callback

	// TODO: add ActionDrop() etc. helpers, maybe hide Actions
	Action Action // requested message actions

	cbs  []*Callback       // callbacks scheduled to run
	tags map[string]string // simple Tag-Value store
}

// MsgContext returns pipe Context inside message m,
// updating m.Value if needed.
func MsgContext(m *msg.Msg) *Context {
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

// Reset resets pc to empty state
func (pc *Context) Reset() {
	// try to re-use tags map
	old_tags := pc.tags
	if old_tags != nil {
		clear(old_tags)
	}

	*pc = Context{}    // set all to zero/nil
	pc.tags = old_tags // try to re-use tags mem
}

// Clear resets pc, but preserves ACTION_BORROW if set.
func (pc *Context) Clear() {
	a := pc.Action
	pc.Reset()
	pc.Action = a & ACTION_BORROW
}

// HasTag returns true iff the context has a Tag set
func (pc *Context) HasTag(tag string) bool {
	if pc.tags == nil {
		return false
	}
	_, ok := pc.tags[tag]
	return ok
}

// GetTag returns given Tag value, or "" if not set
func (pc *Context) GetTag(tag string) string {
	if pc.tags == nil {
		return ""
	}
	return pc.tags[tag]
}

// SetTag set given Tag to given value,
// or to a value of "" if not provided
func (pc *Context) SetTag(tag string, val ...string) {
	tags := pc.Tags()
	if len(val) > 0 {
		tags[tag] = val[0]
	} else {
		tags[tag] = ""
	}
}

// Tags returns a generic string Tag-Value store,
// creating it first if needed.
func (pc *Context) Tags() map[string]string {
	if pc.tags == nil {
		pc.tags = make(map[string]string)
	}
	return pc.tags
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
