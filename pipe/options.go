package pipe

import (
	"reflect"
	"runtime"
	"sync"
	"sync/atomic"

	"github.com/bgpfix/bgpfix/msg"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// Default BGP pipe options
var DefaultOptions = Options{
	Logger: &log.Logger,
	Caps:   true,
	Rbuf:   10,
	Rproc:  1,
	Lbuf:   10,
	Lproc:  1,
}

// BGP pipe options
type Options struct {
	Logger  *zerolog.Logger // if nil logging is disabled
	MsgPool *sync.Pool      // optional pool for msg.Msg

	Caps bool // overwrite pipe.Caps using OPEN messages?

	Rbuf  int // R channels buffer length
	Rproc int // number of R input processors

	Lbuf  int // L channels buffer length
	Lproc int // number of L input processors

	Callbacks []*Callback // message callbacks
	Handlers  []*Handler  // event handlers
}

// Callback represents a function to call for matching BGP messages
type Callback struct {
	Index int // index in Options.Callbacks

	Name    string       // optional name
	Order   int          // the lower the order, the sooner callback is run
	Raw     bool         // if true, run on non-parsed message, before non-raw callbacks
	Enabled *atomic.Bool // if non-nil, disables the callback unless true

	Dst   msg.Dst      // if non-zero, limits the direction
	Types []msg.Type   // if non-empty, limits message types
	Func  CallbackFunc // the function to call
}

// Handler represents a function to call for matching pipe events
type Handler struct {
	Index int // index in Options.Handlers

	Name    string       // optional name
	Order   int          // the lower the order, the sooner handler is run
	Enabled *atomic.Bool // if non-nil, disables the handler unless true

	Types []string    // if non-empty, limits event types
	Func  HandlerFunc // the function to call
}

// CallbackFunc processes message m.
// Optionally returns an Action to add to m's pipe.Context.Action.
type CallbackFunc func(m *msg.Msg) (add_action Action)

// HandlerFunc handles event ev.
// If returns false, unregisters the parent Handler.
type HandlerFunc func(ev *Event) (keep_event bool)

// AddCallbacks adds a callback function using tpl[0] as its template (if non-nil).
// It returns the added Callback, which can be further configured.
func (o *Options) AddCallback(cbf CallbackFunc, tpl ...*Callback) *Callback {
	var cb Callback

	// deep copy the tpl?
	if len(tpl) > 0 && tpl[0] != nil {
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

	cb.Index = len(o.Callbacks)
	o.Callbacks = append(o.Callbacks, &cb)
	return &cb
}

// OnMsg adds a callback for all messages of given types (or all types if not specified).
func (o *Options) OnMsg(cb CallbackFunc, dst msg.Dst, types ...msg.Type) *Callback {
	return o.AddCallback(cb, &Callback{
		Order: 0,
		Dst:   dst,
		Types: types,
	})
}

// OnMsgFirst adds a callback as the first for all messages of given types (or all types if not specified).
func (o *Options) OnMsgFirst(cb CallbackFunc, dst msg.Dst, types ...msg.Type) *Callback {
	return o.AddCallback(cb, &Callback{
		Order: -len(o.Callbacks) - 1,
		Dst:   dst,
		Types: types,
	})
}

// OnMsgLast adds a callback as the last for all messages of given types (or all types if not specified).
func (o *Options) OnMsgLast(cb CallbackFunc, dst msg.Dst, types ...msg.Type) *Callback {
	return o.AddCallback(cb, &Callback{
		Order: len(o.Callbacks) + 1,
		Dst:   dst,
		Types: types,
	})
}

// AddHandler adds a handler function using tpl[0] as its template (if non-nil).
// It returns the added Handler, which can be further configured.
func (o *Options) AddHandler(hf HandlerFunc, tpl ...*Handler) *Handler {
	var h Handler

	// deep copy the tpl?
	if len(tpl) > 0 && tpl[0] != nil {
		h = *tpl[0]
		h.Types = nil
		h.Types = append(h.Types, tpl[0].Types...)
	}

	// all types?
	if len(h.Types) == 0 {
		h.Types = append(h.Types, "")
	}

	// override the function?
	if hf != nil {
		h.Func = hf
	}

	// override the name?
	if len(h.Name) == 0 {
		h.Name = runtime.FuncForPC(reflect.ValueOf(hf).Pointer()).Name()
	}

	h.Index = len(o.Handlers)
	o.Handlers = append(o.Handlers, &h)
	return &h
}

// OnEvent request cb to be called for given event types.
// If no types provided, it requests to call cb on *every* event.
func (o *Options) OnEvent(cb HandlerFunc, types ...string) *Handler {
	return o.AddHandler(cb, &Handler{
		Order: 0,
		Types: types,
	})
}

// OnEventFirst is same as OnEvent but adds cb as the first to run for given types
func (o *Options) OnEventFirst(cb HandlerFunc, types ...string) *Handler {
	return o.AddHandler(cb, &Handler{
		Order: -len(o.Handlers) - 1,
		Types: types,
	})
}

// OnEventLast is same as OnEvent but adds cb as the first to run for given types
func (o *Options) OnEventLast(cb HandlerFunc, types ...string) *Handler {
	return o.AddHandler(cb, &Handler{
		Order: len(o.Callbacks) + 1,
		Types: types,
	})
}

// OnStart request cb to be called after the pipe starts.
func (o *Options) OnStart(cb HandlerFunc) {
	o.OnEvent(cb, EVENT_START)
}

// OnStop request cb to be called when the pipe stops.
func (o *Options) OnStop(cb HandlerFunc) {
	o.OnEvent(cb, EVENT_STOP)
}

// OnEstablished request cb to be called when the BGP session is established.
func (o *Options) OnEstablished(cb HandlerFunc) {
	o.OnEvent(cb, EVENT_ESTABLISHED)
}

// OnParseError request cb to be called on BGP message parse error.
func (o *Options) OnParseError(cb HandlerFunc) {
	o.OnEvent(cb, EVENT_PARSE_ERROR)
}
