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

// UseTags returns message tags inside m, creating them first if needed.
func UseTags(m *msg.Msg) map[string]string {
	return UseContext(m).UseTags()
}

// GetTags returns message tags inside m, iff they exist (or nil).
func GetTags(m *msg.Msg) map[string]string {
	if mx, ok := m.Value.(*Context); ok {
		return mx.tags
	} else {
		return nil
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

// HasTags returns true iff the context has any Tags set
func (mx *Context) HasTags() bool {
	return mx != nil && len(mx.tags) > 0
}

// UseTags returns message tags inside mx, creating them first if needed
func (mx *Context) UseTags() map[string]string {
	if mx == nil {
		return nil
	} else if mx.tags == nil {
		mx.tags = make(map[string]string)
	}
	return mx.tags
}

// GetTags returns message tags inside mx, iff they exist (or nil).
func (mx *Context) GetTags() map[string]string {
	if mx == nil {
		return nil
	} else {
		return mx.tags
	}
}

// HasTag returns true iff the context has a particular Tag set
func (mx *Context) HasTag(tag string) bool {
	if mx.HasTags() {
		_, ok := mx.tags[tag]
		return ok
	} else {
		return false
	}
}

// GetTag returns given Tag value, or "" if not set
func (mx *Context) GetTag(tag string) string {
	if mx.HasTags() {
		return mx.tags[tag]
	} else {
		return ""
	}
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

// DropTag deletes given tag, returning true if it existed
func (mx *Context) DropTag(tag string) bool {
	if mx != nil && len(mx.tags) > 0 {
		if _, ok := mx.tags[tag]; ok {
			delete(mx.tags, tag)
			return true
		}
	}
	return false
}

// DropTags drops all message tags, returning true if any existed
func (mx *Context) DropTags() bool {
	if mx.HasTags() {
		clear(mx.tags)
		return true
	} else {
		return false
	}
}

// ToJSON marshals Context to JSON
func (mx *Context) ToJSON(dst []byte) []byte {
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
