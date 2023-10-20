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
}

// BGP pipe options
type Options struct {
	Logger  *zerolog.Logger // if nil logging is disabled
	MsgPool *sync.Pool      // optional pool for msg.Msg

	Caps bool // overwrite pipe.Caps using OPEN messages?

	ReverseR bool // reverse the processing order for R lines?
	ReverseL bool // reverse the processing order for L lines?

	Callbacks []*Callback // message callbacks
	Handlers  []*Handler  // event handlers
	Inputs    []*Input    // pipe inputs (message processors)
}

// Callback represents a function to call for matching BGP messages
type Callback struct {
	Id      int          // optional callback id number (zero means none)
	Name    string       // optional name
	Order   int          // the lower the order, the sooner callback is run
	Enabled *atomic.Bool // if non-nil, disables the callback unless true

	Pre  bool // run before non-pre callbacks?
	Raw  bool // if true, do not parse the message (which may already be parsed, but for other reasons)
	Post bool // run after non-post callbacks?

	Dst   msg.Dst      // if non-zero, limits the direction
	Types []msg.Type   // if non-empty, limits message types
	Func  CallbackFunc // the function to call
}

// Handler represents a function to call for matching pipe events
type Handler struct {
	Id      int          // optional handler id number (zero means none)
	Name    string       // optional name
	Order   int          // the lower the order, the sooner handler is run
	Enabled *atomic.Bool // if non-nil, disables the handler unless true

	Pre  bool // run before non-pre handlers?
	Post bool // run after non-post handlers?

	Dst   msg.Dst     // if non-zero, limits the direction
	Types []string    // if non-empty, limits event types
	Func  HandlerFunc // the function to call
}

// CallbackFunc processes message m.
// Optionally returns an Action to add to m's pipe.Context.Action.
type CallbackFunc func(m *msg.Msg) (add_action Action)

// HandlerFunc handles event ev.
// If returns false, unregisters the parent Handler for all Types.
type HandlerFunc func(ev *Event) (keep_event bool)

// AddCallbacks adds a callback function using tpl as its template (if non-nil).
// It returns the added Callback, which can be further configured.
func (o *Options) AddCallback(cbf CallbackFunc, tpl *Callback) *Callback {
	var cb Callback

	// deep copy the tpl?
	if tpl != nil {
		cb = *tpl
		cb.Types = nil
		cb.Types = append(cb.Types, tpl.Types...)
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

// OnMsg adds a callback for all messages of given types (or all types if not specified).
func (o *Options) OnMsg(cbf CallbackFunc, dst msg.Dst, types ...msg.Type) *Callback {
	return o.AddCallback(cbf, &Callback{
		Order: len(o.Callbacks) + 1,
		Dst:   dst,
		Types: types,
	})
}

// OnMsgPre is like OnMsg but requests to run cb before other callbacks
func (o *Options) OnMsgPre(cbf CallbackFunc, dst msg.Dst, types ...msg.Type) *Callback {
	return o.AddCallback(cbf, &Callback{
		Pre:   true,
		Order: -len(o.Callbacks) - 1,
		Dst:   dst,
		Types: types,
	})
}

// OnMsgPost is like OnMsg but requests to run cb after other callbacks
func (o *Options) OnMsgPost(cbf CallbackFunc, dst msg.Dst, types ...msg.Type) *Callback {
	return o.AddCallback(cbf, &Callback{
		Post:  true,
		Order: len(o.Callbacks) + 1,
		Dst:   dst,
		Types: types,
	})
}

// AddHandler adds a handler function using tpl as its template (if non-nil).
// It returns the added Handler, which can be further configured.
func (o *Options) AddHandler(hdf HandlerFunc, tpl *Handler) *Handler {
	var h Handler

	// deep copy the tpl?
	if tpl != nil {
		h = *tpl
		h.Types = nil
		h.Types = append(h.Types, tpl.Types...)
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

// AddInput adds pipe Input
func (o *Options) AddInput(dst msg.Dst, tpl *Input) *Input {
	var pi Input

	// deep copy the tpl?
	if tpl != nil {
		pi = *tpl
	}

	// override the name?
	if len(pi.Name) == 0 {
		if pc, _, _, ok := runtime.Caller(1); ok {
			pi.Name = runtime.FuncForPC(pc).Name()
		}
	}

	o.Inputs = append(o.Inputs, &pi)
	return &pi
}
