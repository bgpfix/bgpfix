package pipe

import (
	"fmt"
	"reflect"
	"runtime"
	"sync"
	"sync/atomic"

	"github.com/bgpfix/bgpfix/dir"
	"github.com/bgpfix/bgpfix/filter"
	"github.com/bgpfix/bgpfix/msg"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"golang.org/x/time/rate"
)

// Default BGP pipe options
var DefaultOptions = Options{
	Logger: &log.Logger,
	Caps:   true,
}

// BGP pipe options
type Options struct {
	Logger  *zerolog.Logger // if nil logging is disabled
	MsgPool *sync.Pool      // optional pool for msg.Msg

	Caps bool // overwrite pipe.Caps with the capabilities negotiated in OPEN messages?

	Callbacks []*Callback // message callbacks
	Handlers  []*Handler  // event handlers
	Inputs    []*Input    // input processors
}

// Callback represents a function to call for matching BGP messages
type Callback struct {
	Id      int          // optional callback id number (zero means none)
	Name    string       // optional name
	Order   int          // the lower the order, the sooner callback is run
	Enabled *atomic.Bool // if non-nil, disables the callback unless true
	Dropped bool         // if true, permanently drops (unregisters) the callback

	Pre  bool // run before non-pre callbacks?
	Raw  bool // if true, do not parse the message (which may already be parsed, but for other reasons)
	Post bool // run after non-post callbacks?

	Dir       dir.Dir        // if non-zero, limits the direction
	Types     []msg.Type     // if non-empty, limits message types
	Filter    *filter.Filter // if non-nil, skips messages not matching the filter
	LimitRate *rate.Limiter  // if non-nil, limits the rate of callback invocations
	LimitSkip bool           // if true, skips the message when rate limit exceeded (else blocks)

	Func CallbackFunc // the function to call
}

// Handler represents a function to call for matching pipe events
type Handler struct {
	Id      int          // optional handler id number (zero means none)
	Name    string       // optional name
	Order   int          // the lower the order, the sooner handler is run
	Enabled *atomic.Bool // if non-nil, disables the handler unless true
	Dropped bool         // if true, permanently drops (unregisters) the handler

	Pre  bool // run before non-pre handlers?
	Post bool // run after non-post handlers?

	Dir   dir.Dir     // if non-zero, limits the direction
	Types []string    // if non-empty, limits event types
	Func  HandlerFunc // the function to call
}

// CallbackFunc processes message m.
// Return false to drop the message.
type CallbackFunc func(m *msg.Msg) (keep_message bool)

// HandlerFunc handles event ev.
// Return false to unregister the handler (all types).
type HandlerFunc func(ev *Event) (keep_handler bool)

// AddCallbacks adds a callback function using tpl as its template (if present).
// It returns the added Callback, which can be further configured.
func (o *Options) AddCallback(cbf CallbackFunc, tpl ...*Callback) *Callback {
	var cb Callback

	// deep copy the tpl?
	if len(tpl) > 0 {
		cb = *tpl[0]
		cb.Types = nil
		cb.Types = append(cb.Types, tpl[0].Types...)
	}

	// override the function?
	if cbf != nil {
		cb.Func = cbf
	}

	// override the name?
	if len(cb.Name) == 0 {
		cb.Name = runtime.FuncForPC(reflect.ValueOf(cbf).Pointer()).Name()
	}

	o.Callbacks = append(o.Callbacks, &cb)
	return &cb
}

// Enable sets cb.Enabled to true and returns true. If cb.Enabled is nil, returns false.
func (cb *Callback) Enable() bool {
	if cb == nil || cb.Enabled == nil {
		return false
	} else {
		cb.Enabled.Store(true)
		return true
	}
}

// Disable sets cb.Enabled to false and returns true. If cb.Enabled is nil, returns false.
func (cb *Callback) Disable() bool {
	if cb == nil || cb.Enabled == nil {
		return false
	} else {
		cb.Enabled.Store(false)
		return true
	}
}

// Drop drops the callback, permanently unregistering it from running
func (cb *Callback) Drop() {
	if cb != nil {
		cb.Dropped = true
	}
}

// String returns callback name and id as string
func (cb *Callback) String() string {
	return fmt.Sprintf("CB%d:%s", cb.Id, cb.Name)
}

// OnMsg adds a callback for all messages of given types (or all types if not specified).
func (o *Options) OnMsg(cbf CallbackFunc, dir dir.Dir, types ...msg.Type) *Callback {
	return o.AddCallback(cbf, &Callback{
		Order: len(o.Callbacks) + 1,
		Dir:   dir,
		Types: types,
	})
}

// OnMsgPre is like OnMsg but requests to run cb before other callbacks
func (o *Options) OnMsgPre(cbf CallbackFunc, dir dir.Dir, types ...msg.Type) *Callback {
	return o.AddCallback(cbf, &Callback{
		Pre:   true,
		Order: -len(o.Callbacks) - 1,
		Dir:   dir,
		Types: types,
	})
}

// OnMsgPost is like OnMsg but requests to run cb after other callbacks
func (o *Options) OnMsgPost(cbf CallbackFunc, dir dir.Dir, types ...msg.Type) *Callback {
	return o.AddCallback(cbf, &Callback{
		Post:  true,
		Order: len(o.Callbacks) + 1,
		Dir:   dir,
		Types: types,
	})
}

// AddHandler adds a handler function using tpl as its template (if present).
// It returns the added Handler, which can be further configured.
func (o *Options) AddHandler(hdf HandlerFunc, tpl ...*Handler) *Handler {
	var h Handler

	// deep copy the tpl?
	if len(tpl) > 0 {
		h = *tpl[0]
		h.Types = nil
		h.Types = append(h.Types, tpl[0].Types...)
	}

	// all types?
	if len(h.Types) == 0 {
		h.Types = []string{"*"}
	}

	// override the function?
	if hdf != nil {
		h.Func = hdf
	}

	// override the name?
	if len(h.Name) == 0 {
		h.Name = runtime.FuncForPC(reflect.ValueOf(hdf).Pointer()).Name()
	}

	o.Handlers = append(o.Handlers, &h)
	return &h
}

// String returns handler name and id as string
func (h *Handler) String() string {
	return fmt.Sprintf("EV%d:%s", h.Id, h.Name)
}

// Enable sets h.Enabled to true and returns true. If h.Enabled is nil, returns false.
func (h *Handler) Enable() bool {
	if h == nil || h.Enabled == nil {
		return false
	} else {
		h.Enabled.Store(true)
		return true
	}
}

// Disable sets h.Enabled to false and returns true. If h.Enabled is nil, returns false.
func (h *Handler) Disable() bool {
	if h == nil || h.Enabled == nil {
		return false
	} else {
		h.Enabled.Store(false)
		return true
	}
}

// Drop drops the handler, permanently unregistering it from running
func (h *Handler) Drop() {
	if h != nil {
		h.Dropped = true
	}
}

// OnEvent request hdf to be called for given event types.
// If no types provided, it requests to call hdf on *every* event.
func (o *Options) OnEvent(hdf HandlerFunc, types ...string) *Handler {
	return o.AddHandler(hdf, &Handler{
		Order: len(o.Handlers) + 1,
		Types: types,
	})
}

// OnEventPre is like OnEvent but requests to run hdf before other handlers
func (o *Options) OnEventPre(hdf HandlerFunc, types ...string) *Handler {
	return o.AddHandler(hdf, &Handler{
		Pre:   true,
		Order: -len(o.Handlers) - 1,
		Types: types,
	})
}

// OnEventPost is like OnEvent but requests to run hdf after other handlers
func (o *Options) OnEventPost(hdf HandlerFunc, types ...string) *Handler {
	return o.AddHandler(hdf, &Handler{
		Post:  true,
		Order: len(o.Handlers) + 1,
		Types: types,
	})
}

// OnStart request hdf to be called after the pipe starts.
func (o *Options) OnStart(hdf HandlerFunc) *Handler {
	return o.OnEvent(hdf, EVENT_START)
}

// OnStop request hdf to be called when the pipe stops.
func (o *Options) OnStop(hdf HandlerFunc) *Handler {
	return o.OnEvent(hdf, EVENT_STOP)
}

// OnEstablished request hdf to be called when the BGP session is established.
func (o *Options) OnEstablished(hdf HandlerFunc) *Handler {
	return o.OnEvent(hdf, EVENT_ESTABLISHED)
}

// OnParseError request hdf to be called on BGP message parse error.
func (o *Options) OnParseError(hdf HandlerFunc) *Handler {
	return o.OnEvent(hdf, EVENT_PARSE)
}

// AddInput adds input processor for given pipe direction, with optional details in tpl.
func (o *Options) AddInput(dst dir.Dir, tpl ...*Input) *Input {
	var in Input

	// copy the tpl?
	if len(tpl) > 0 {
		in = *tpl[0]
	}

	// override the name?
	if len(in.Name) == 0 {
		if pc, _, _, ok := runtime.Caller(1); ok {
			in.Name = runtime.FuncForPC(pc).Name()
		}
	}

	// input
	if in.In == nil {
		in.In = make(chan *msg.Msg, 100)
	}

	// dir
	if dst == dir.DIR_L {
		in.Dir = dir.DIR_L
	} else {
		in.Dir = dir.DIR_R
	}

	o.Inputs = append(o.Inputs, &in)
	return &in
}
