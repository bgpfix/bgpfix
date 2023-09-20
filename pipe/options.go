package pipe

import (
	"reflect"
	"runtime"
	"sync"

	"github.com/bgpfix/bgpfix/msg"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// Default BGP pipe options
var DefaultOptions = Options{
	Logger: &log.Logger,
	Caps:   true,
	Rlen:   10,
	Rproc:  1,
	Llen:   10,
	Lproc:  1,
}

// BGP pipe options
type Options struct {
	Logger  *zerolog.Logger // if nil logging is disabled
	MsgPool *sync.Pool      // optional pool for msg.Msg

	Caps bool // overwrite pipe.Caps using OPEN messages?

	Rlen  int // R channel length
	Rproc int // number of R input handlers

	Llen  int // L channel length
	Lproc int // number of L input handlers

	Callbacks []*Callback            // message callbacks
	Events    map[string][]EventFunc // event handlers
}

// Callback represents a function to call for given messages
type Callback struct {
	Name  string // optional name
	Order int    // the lower the order, the sooner callback is run
	Raw   bool   // if true, run on non-parsed message, before non-raw callbacks

	Dst   msg.Dst      // if non-zero, limits the direction
	Types []msg.Type   // if non-empty, limits message types
	Func  CallbackFunc // the function to call
}

// CallbackFunc processes message m, optionally returning an Action
// to add to the pipe.Context.Action value.
type CallbackFunc func(m *msg.Msg) (add_action Action)

// EventFunc handles event ev.
// If returns false, unregisters the callback from future calls.
type EventFunc func(ev *Event) (keep_event bool)

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

	o.Callbacks = append(o.Callbacks, &cb)
	return &cb
}

// OnMsg adds a callback for all messages of given types (or all types if not specified).
func (o *Options) OnMsg(cb CallbackFunc, dst msg.Dst, types ...msg.Type) *Callback {
	return o.AddCallback(cb, &Callback{
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

// OnEvent request cb to be called for given event types etypes.
// If no etypes is provided, it requests to call cb on *every* event.
func (o *Options) OnEvent(cb EventFunc, etypes ...string) {
	if len(etypes) == 0 {
		o.Events[""] = append(o.Events[""], cb)
	} else {
		for _, et := range etypes {
			o.Events[et] = append(o.Events[et], cb)
		}
	}
}

// OnStart request cb to be called after the pipe starts.
func (o *Options) OnStart(cb EventFunc) {
	o.OnEvent(cb, EVENT_START)
}

// OnStop request cb to be called when the pipe stops.
func (o *Options) OnStop(cb EventFunc) {
	o.OnEvent(cb, EVENT_STOP)
}

// OnEstablished request cb to be called when the pipe records OPEN+KEEPALIVE in both directions.
func (o *Options) OnEstablished(cb EventFunc) {
	o.OnEvent(cb, EVENT_ESTABLISHED)
}

// OnParseError request cb to be called on BGP message parse error.
func (o *Options) OnParseError(cb EventFunc) {
	o.OnEvent(cb, EVENT_PARSE_ERROR)
}
