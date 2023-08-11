package pipe

import (
	"context"
	"sort"
	"sync"
	"sync/atomic"

	"github.com/bgpfix/bgpfix/msg"
	"github.com/rs/zerolog"
)

// Pipe processes BGP messages sent/received from a BGP peer, or
// exchanged between two BGP peers.
//
// Use NewPipe() to get a new object, then modify its .Options,
// and call Start() to start the message flow. For each direction
// available under .Rx and .Tx in the pipe, write incoming messages
// to the .In channel, and read processed messages from the .Out channel.
type Pipe struct {
	zerolog.Logger

	ctx    context.Context
	cancel context.CancelFunc

	msgpool *sync.Pool     // message pool
	rxwg    sync.WaitGroup // RX Input handler
	txwg    sync.WaitGroup // TX Input handler
	evwg    sync.WaitGroup // event handler

	started atomic.Bool // true iff Start() called
	stopped atomic.Bool // true iff Stop() called

	// do not use before Start
	Rx *Dir // messages from peer; do not use before Start()
	Tx *Dir // messages to peer; do not use before Start()

	// do not modify after Start
	Options Options // BGP pipe options

	// use anytime, thread-safe
	Caps   msg.Caps    // BGP capability context
	Events chan *Event // pipe events
}

// NewPipe returns a new pipe, which can be configured through .Options.
// To start/stop the pipe, call Start() and Stop().
func NewPipe(ctx context.Context) *Pipe {
	p := &Pipe{}
	p.ctx, p.cancel = context.WithCancel(ctx)

	p.Options = DefaultOptions
	p.Options.Events = make(map[any][]EventFunc)

	p.Caps.Init() // NB: make it thread-safe
	p.Events = make(chan *Event, 10)

	return p
}

func (p *Pipe) apply(opts *Options) {
	p.Logger = opts.Logger

	if opts.MsgPool != nil {
		p.msgpool = opts.MsgPool
	} else {
		p.msgpool = new(sync.Pool)
	}

	p.Rx = &Dir{p: p, dir: msg.RX}
	if opts.RxInput != nil {
		p.Rx.In = opts.RxInput
	} else {
		p.Rx.In = make(chan *msg.Msg, opts.RxLen)
	}

	if opts.RxOutput != nil {
		p.Rx.Out = opts.RxOutput
	} else {
		p.Rx.Out = make(chan *msg.Msg, opts.RxLen)
	}

	p.Tx = &Dir{p: p, dir: msg.TX}
	if opts.TxInput != nil {
		p.Tx.In = opts.TxInput
	} else {
		p.Tx.In = make(chan *msg.Msg, opts.TxLen)
	}

	if opts.TxOutput != nil {
		p.Tx.Out = opts.TxOutput
	} else {
		p.Tx.Out = make(chan *msg.Msg, opts.TxLen)
	}

	// rewrite callbacks to sides, respecting their order
	sort.SliceStable(opts.Callbacks, func(i, j int) bool {
		cbi := opts.Callbacks[i]
		cbj := opts.Callbacks[j]
		if cbi.Raw != cbj.Raw {
			return cbi.Raw
		} else {
			return cbi.Order < cbj.Order
		}
	})
	for _, cb := range opts.Callbacks {
		if cb == nil {
			continue
		}
		switch cb.Dir {
		case msg.TXRX:
			p.Tx.addCallback(cb)
			p.Rx.addCallback(cb)
		case msg.TX:
			p.Tx.addCallback(cb)
		case msg.RX:
			p.Rx.addCallback(cb)
		}
	}

	// very first OPEN handlers
	opts.Events[EVENT_RX_OPEN] = append([]EventFunc{p.open}, opts.Events[EVENT_RX_OPEN]...)
	opts.Events[EVENT_TX_OPEN] = append([]EventFunc{p.open}, opts.Events[EVENT_TX_OPEN]...)
}

// Start starts given number of rx/tx message handlers in background,
// by default rx/tx = 1/1 (single-threaded, strictly ordered processing).
func (p *Pipe) Start() {
	if p.started.Swap(true) || p.stopped.Load() {
		return // already started or stopped
	}

	// apply opts
	opts := &p.Options
	p.apply(opts)

	// start RX handlers
	for i := 0; i < opts.RxHandlers; i++ {
		p.rxwg.Add(1)
		go p.Rx.Handler(&p.rxwg)
	}
	go func() {
		p.rxwg.Wait() // @1 after s.Rx.Input is closed (or no handlers)
		p.Rx.CloseOutput()
	}()

	// start TX handlers
	for i := 0; i < opts.TxHandlers; i++ {
		p.txwg.Add(1)
		go p.Tx.Handler(&p.txwg)
	}
	go func() {
		p.txwg.Wait() // @1 after s.Tx.Input is closed (or no handlers)
		p.Tx.CloseOutput()
	}()

	// start event handlers
	p.evwg.Add(1)
	go p.eventHandler(&p.evwg)

	// stop everything on context cancel
	go func() {
		<-p.ctx.Done()
		p.Stop()
	}()

	// publish the start event!
	go p.Event(EVENT_START, nil)
}

// open emits EVENT_OPEN when both sides have seen OPEN + fills p.Caps if enabled
func (p *Pipe) open(_ *Pipe, ev *Event) bool {
	// already seen OPEN for both directions?
	rx, tx := p.Rx.Open.Load(), p.Tx.Open.Load()
	if rx == nil || tx == nil {
		return true // not yet
	}

	// find out common caps
	if p.Options.Caps {
		p.Caps.Clear()
		p.Caps.SetFrom(rx.Caps)

		// verify vs. what we sent
		p.Caps.Each(func(i int, cc msg.CapCode, rxcap msg.Cap) {
			txcap := tx.Caps.Get(cc)

			// no common support for cc at all? delete it
			if rxcap == nil || txcap == nil {
				p.Caps.Drop(cc)
				return
			}

			// dive into rxcap vs txcap
			if common := rxcap.Common(txcap); common != nil {
				p.Caps.Set(cc, common)
			}
		})
	}

	// announce both OPENs were seen, Caps ready for use
	p.Event(EVENT_OPEN, nil)

	// no more calls to this callback
	return false
}

// Stop stops all handlers and blocks till handlers finish.
// Pipe must not be used again past this point.
// Closes all input channels, which should eventually close all output channels,
// possibly after this function returns.
func (p *Pipe) Stop() {
	if p.stopped.Swap(true) || !p.started.Load() {
		return // already stopped, or not started yet
	}

	// publish the event (best-effort)
	go p.Event(EVENT_STOP, nil)

	// yank the cable out of blocked calls (hopefully)
	p.cancel()

	// stop the input handlers and wait for them to finish
	p.Rx.CloseInput()
	p.Tx.CloseInput()
	p.rxwg.Wait()
	p.txwg.Wait()
	// NB: now @1 will close the RX/TX outputs

	// safely stop the event handler and wait for it to finish
	func() {
		defer func() { recover() }()
		close(p.Events)
	}()
	p.evwg.Wait()
}

// Wait blocks until all handlers finish.
func (p *Pipe) Wait() {
	p.rxwg.Wait()
	p.txwg.Wait()
	p.evwg.Wait()
}

// Started returns true iff Start() has already been called = pipe is (being) started.
func (p *Pipe) Started() bool {
	return p.started.Load()
}

// Stopped returns true iff Stop() has already been called = pipe is (being) stopped.
func (p *Pipe) Stopped() bool {
	return p.stopped.Load()
}

// Get returns empty msg from pool, or a new msg object
func (p *Pipe) Get(typ ...msg.Type) (m *msg.Msg) {
	v := p.msgpool.Get()
	if v == nil {
		m = msg.NewMsg()
	} else {
		m = v.(*msg.Msg)
	}

	// prepare the upper layer?
	if len(typ) > 0 {
		m.SetUp(typ[0])
	}

	return m
}

// Put resets msg and returns it to pool, which might free it
func (p *Pipe) Put(m *msg.Msg) {
	if m != nil && ActionNot(m, ACTION_KEEP) {
		m.Reset()
		p.msgpool.Put(m)
	}
}

// Write writes raw BGP data to p.Rx.Input
func (p *Pipe) Write(b []byte) (n int, err error) {
	return p.Rx.Write(b)
}

// Read reads raw BGP data from p.Tx.Output
func (p *Pipe) Read(b []byte) (n int, err error) {
	return p.Tx.Read(b)
}
