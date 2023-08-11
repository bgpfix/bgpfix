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
	Logger:     log.Logger,
	RxLen:      10,
	RxHandlers: 1,
	TxLen:      10,
	TxHandlers: 1,
	Caps:       true,
}

// BGP pipe options
type Options struct {
	Logger  zerolog.Logger // use zerolog.Nop to disable logging
	MsgPool *sync.Pool     // optional pool for msg.Msg

	Tstamp bool // add timestamps to messages?
	Caps   bool // fill pipe.Caps using OPEN messages?

	RxInput    chan *msg.Msg // RxInput channel (nil=create)
	RxOutput   chan *msg.Msg // RxOutput channel (nil=create)
	RxLen      int           // Rx channel length (if need to create)
	RxHandlers int           // number of RX handler goroutines

	TxInput    chan *msg.Msg // TxInput channel (nil=create)
	TxOutput   chan *msg.Msg // TxOutput channel (nil=create)
	TxLen      int           // Tx channel length (if need to create)
	TxHandlers int           // number of TX handler goroutines

	Callbacks []*Callback         // BGP message callbacks
	Events    map[any][]EventFunc // pipe event handlers
}

// Callback represents a function to call for given messages
type Callback struct {
	Name  string // optional name
	Order int    // the lower the order, the sooner callback is run
	Raw   bool   // if true, run ahead of non-raw callbacks on non-parsed message

	Dir   msg.Dir      // if non-zero, limits the direction
	Types []msg.Type   // if non-empty, limits message types
	Func  CallbackFunc // the function to call
}

// CallbackFunc processes message m, optionally setting m.Action.
type CallbackFunc func(p *Pipe, m *msg.Msg)

// EventFunc handles event ev.
// If returns keep=false, unregisters the callback from future calls.
type EventFunc func(p *Pipe, ev *Event) (keep bool)

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

// OnTxRx adds a callback for all messages of given types
func (o *Options) OnTxRx(cb CallbackFunc, types ...msg.Type) *Callback {
	return o.AddCallback(cb, &Callback{
		Types: types,
	})
}

// OnTx adds a callback for TX messages of given types
func (o *Options) OnTx(cb CallbackFunc, types ...msg.Type) *Callback {
	return o.AddCallback(cb, &Callback{
		Dir:   msg.TX,
		Types: types,
	})
}

// OnRx adds a callback for all RX messages of given types
func (o *Options) OnRx(cb CallbackFunc, types ...msg.Type) *Callback {
	return o.AddCallback(cb, &Callback{
		Dir:   msg.RX,
		Types: types,
	})
}

// OnTxRxFirst adds a callback as the first for all messages of given types
func (o *Options) OnTxRxFirst(cb CallbackFunc, types ...msg.Type) *Callback {
	return o.AddCallback(cb, &Callback{
		Order: -len(o.Callbacks) - 1,
		Types: types,
	})
}

// OnTxFirst adds a callback as the first for TX messages of given types
func (o *Options) OnTxFirst(cb CallbackFunc, types ...msg.Type) *Callback {
	return o.AddCallback(cb, &Callback{
		Order: -len(o.Callbacks) - 1,
		Dir:   msg.TX,
		Types: types,
	})
}

// OnRxFirst adds a callback as the first for RX messages of given types
func (o *Options) OnRxFirst(cb CallbackFunc, types ...msg.Type) *Callback {
	return o.AddCallback(cb, &Callback{
		Order: -len(o.Callbacks) - 1,
		Dir:   msg.RX,
		Types: types,
	})
}

// OnTxRxLast adds a callback as the last for all messages of given types
func (o *Options) OnTxRxLast(cb CallbackFunc, types ...msg.Type) *Callback {
	return o.AddCallback(cb, &Callback{
		Order: len(o.Callbacks) + 1,
		Types: types,
	})
}

// OnTxLast adds a callback as the last for TX messages of given types
func (o *Options) OnTxLast(cb CallbackFunc, types ...msg.Type) *Callback {
	return o.AddCallback(cb, &Callback{
		Order: len(o.Callbacks) + 1,
		Dir:   msg.TX,
		Types: types,
	})
}

// OnRxLast adds a callback as the last for all RX messages of given types
func (o *Options) OnRxLast(cb CallbackFunc, types ...msg.Type) *Callback {
	return o.AddCallback(cb, &Callback{
		Order: len(o.Callbacks) + 1,
		Dir:   msg.RX,
		Types: types,
	})
}

// OnEvent request cb to be called for given event types etypes.
// Remember to use *references* in etypes (unless you know what you are doing).
// If no etypes is provided, it requests to call cb on *every* event.
func (o *Options) OnEvent(cb EventFunc, etypes ...any) {
	if len(etypes) == 0 {
		o.Events[nil] = append(o.Events[nil], cb)
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

// OnOpen request cb to be called when the pipe records OPEN in both directions.
func (o *Options) OnOpen(cb EventFunc) {
	o.OnEvent(cb, EVENT_OPEN)
}
