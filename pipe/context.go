package pipe

import (
	"github.com/bgpfix/bgpfix/json"
	"github.com/bgpfix/bgpfix/msg"
)

// Context tracks message processing in a Pipe, stored in Msg.Value.
type Context struct {
	Pipe     *Pipe       // pipe processing the message
	Input    *Input      // input processing the message (message source)
	Callback *Callback   // currently running callback
	cbs      []*Callback // all callbacks scheduled to run

	// exported to JSON

	Action Action            // requested message actions
	tags   map[string]string // message tags (essentially a Key-Value store)
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

// HasContext returns true iff m has a Context
func HasContext(m *msg.Msg) bool {
	_, ok := m.Value.(*Context)
	return ok
}

// MsgTags returns message Tags inside m, creating them first if needed
func MsgTags(m *msg.Msg) map[string]string {
	mx := MsgContext(m)
	return mx.Tags()
}

// HasTags returns true iff m has a Context and non-empty Tags
func HasTags(m *msg.Msg) bool {
	mx, ok := m.Value.(*Context)
	return ok && len(mx.tags) > 0
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

// Tags returns message Tags inside mx, creating them first if needed
func (mx *Context) Tags() map[string]string {
	if mx == nil {
		return nil
	} else if mx.tags == nil {
		mx.tags = make(map[string]string)
	}
	return mx.tags
}

// HasTags returns true iff the context has any Tags set
func (mx *Context) HasTags() bool {
	return mx != nil && len(mx.tags) > 0
}

// HasTag returns true iff the context has a particular Tag set
func (mx *Context) HasTag(tag string) bool {
	if !mx.HasTags() {
		return false
	}
	_, ok := mx.tags[tag]
	return ok
}

// GetTag returns given Tag value, or "" if not set
func (mx *Context) GetTag(tag string) string {
	if !mx.HasTags() {
		return ""
	}
	return mx.tags[tag]
}

// SetTag set given Tag to given value.
func (mx *Context) SetTag(tag string, val string) {
	if mx == nil {
		return
	} else if mx.tags == nil {
		mx.tags = make(map[string]string)
	}
	mx.tags[tag] = val
}

// DropTags drops all message tags
func (mx *Context) DropTags() {
	mx.tags = nil
}

// ToJSON marshals Context to JSON
func (mx *Context) ToJSON(dst []byte) []byte {
	if mx.Action == 0 && len(mx.tags) == 0 {
		return append(dst, `null`...)
	}

	dst = append(dst, '{')
	first := len(dst)

	if mx.Action != 0 {
		dst = append(dst, `"ACTION":`...)
		dst = mx.Action.ToJSON(dst)
	}

	for key, val := range mx.tags {
		if key == "ACTION" {
			continue
		}
		if len(dst) == first {
			dst = append(dst, `"`...)
		} else {
			dst = append(dst, `,"`...)
		}
		dst = json.Ascii(dst, json.B(key))
		dst = append(dst, `":"`...)
		dst = json.Ascii(dst, json.B(val))
		dst = append(dst, '"')
	}

	return append(dst, '}')
}

// FromJSON unmarshals Context from JSON
func (mx *Context) FromJSON(src []byte) error {
	return json.ObjectEach(src, func(key string, val []byte, typ json.Type) error {
		// special case: message action
		if key == "ACTION" {
			return mx.Action.FromJSON(val)
		} else {
			mx.SetTag(key, string(val))
			return nil
		}
	})
}
