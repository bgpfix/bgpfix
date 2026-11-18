package pipe

import (
	"strings"

	"github.com/bgpfix/bgpfix/json"
	"github.com/bgpfix/bgpfix/meta"
	"github.com/bgpfix/bgpfix/msg"
)

// Context tracks message processing in a Pipe, stored in Msg.Value.
type Context struct {
	Pipe     *Pipe       // pipe processing the message
	Input    *Input      // input processing the message (message source)
	Callback *Callback   // currently running callback
	cbs      []*Callback // all callbacks scheduled to run

	// exported to JSON

	Action Action    // requested message actions
	Tags   meta.Tags // message tags
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

// GetTags returns the tags of m, if any
func GetTags(m *msg.Msg) meta.Tags {
	if mx, ok := m.Value.(*Context); ok {
		return mx.Tags
	}
	return nil
}

// Take takes the message from the pipe: when the callback returns, the pipe forgets
// it, and you own it. Eg. hold it and send it later with Input.WriteMsg, which
// processes it as new, or drop it with Pipe.PutMsg. Call only from a callback.
func (mx *Context) Take() {
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
	mx.Tags = mx.Tags[:0]
}

// ToJSON marshals Context to JSON
func (mx *Context) ToJSON(dst []byte) []byte {
	dst = append(dst, '{')
	first := len(dst)

	if mx.Action != 0 {
		dst = append(dst, `"ACTION":`...)
		dst = mx.Action.ToJSON(dst)
	}

	for _, t := range mx.Tags {
		key, val := t.Key, t.Val
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
		if key == "ACTION" {
			return nil // NB: export-only, a feed must not choose how its messages are processed
		} else if len(val) == 0 {
			return nil // ignore empty values
		} else {
			// NB: key aliases src (see json.ObjectEach), which the reader re-uses: copy it
			mx.Tags.Set(strings.Clone(key), string(val))
			return nil
		}
	})
}
