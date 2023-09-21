// Package pipe provides BGP message processing with callbacks.
package pipe

import (
	"context"
	"sort"
	"sync"
	"sync/atomic"

	"github.com/bgpfix/bgpfix/caps"
	"github.com/bgpfix/bgpfix/msg"
	"github.com/puzpuzpuz/xsync/v2"
	"github.com/rs/zerolog"
)

// Pipe processes BGP messages exchanged between two BGP peers,
// L (for "left" or "local") and R (for "right" or "remote"),
// allowing for building callback-based pipelines in both directions,
// plus an internal event system. It can also track OPEN messages
// to find out the negotiated BGP capabilities on a session.
//
// Write messages destined for R to Pipe.R.In, and read the results
// from Pipe.R.Out. Similarly, write messages destined for L to
// Pipe.L.In, and read the results from Pipe.L.Out.
//
// Use NewPipe() to get a new object and modify its Pipe.Options.
// Then call Pipe.Start() to start the message flow.
type Pipe struct {
	*zerolog.Logger

	ctx    context.Context
	cancel context.CancelFunc

	started atomic.Bool // true iff Start() called
	stopped atomic.Bool // true iff Stop() called

	pool *sync.Pool     // message pool
	lwg  sync.WaitGroup // L Input handlers
	rwg  sync.WaitGroup // R Input handlers

	events chan *Event    // pipe events
	evwg   sync.WaitGroup // event handler

	Options Options    // pipe options; modify before Start()
	Caps    caps.Caps  // BGP capability context; always thread-safe
	L       *Direction // messages for L, call Start() before use
	R       *Direction // messages for R; call Start() before use

	// generic Key-Value store, always thread-safe
	KV *xsync.MapOf[string, any]
}

// NewPipe returns a new pipe, which can be configured through its Options.
// To start/stop the pipe, call Start() and Stop().
func NewPipe(ctx context.Context) *Pipe {
	p := &Pipe{}
	p.ctx, p.cancel = context.WithCancel(ctx)

	p.Options = DefaultOptions
	p.Options.Events = make(map[string][]EventFunc)

	p.L = &Direction{
		Pipe: p,
		Dst:  msg.DST_L,
	}

	p.R = &Direction{
		Pipe: p,
		Dst:  msg.DST_R,
	}

	p.L.Opposite = p.R
	p.R.Opposite = p.L

	p.Caps.Init() // NB: make it thread-safe
	p.events = make(chan *Event, 10)

	p.KV = xsync.NewMapOf[any]()

	return p
}

func (p *Pipe) apply(opts *Options) {
	if opts.Logger != nil {
		p.Logger = opts.Logger
	} else {
		l := zerolog.Nop()
		p.Logger = &l
	}
	p.Logger = opts.Logger

	if opts.MsgPool != nil {
		p.pool = opts.MsgPool
	} else {
		p.pool = new(sync.Pool)
	}

	if p.L.In == nil {
		p.L.In = make(chan *msg.Msg, opts.Llen)
	}
	if p.L.Out == nil {
		p.L.Out = make(chan *msg.Msg, opts.Llen)
	}

	if p.R.In == nil {
		p.R.In = make(chan *msg.Msg, opts.Rlen)
	}
	if p.R.Out == nil {
		p.R.Out = make(chan *msg.Msg, opts.Rlen)
	}

	// rewrite callbacks to sides, respecting their options
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
		switch cb.Dst {
		case msg.DST_LR:
			p.L.addCallback(cb)
			p.R.addCallback(cb)
		case msg.DST_L:
			p.L.addCallback(cb)
		case msg.DST_R:
			p.R.addCallback(cb)
		}
	}

	// prepend very first EVENT_ALIVE_* handlers
	opts.Events[EVENT_ALIVE_R] = append([]EventFunc{p.alive}, opts.Events[EVENT_ALIVE_R]...)
	opts.Events[EVENT_ALIVE_L] = append([]EventFunc{p.alive}, opts.Events[EVENT_ALIVE_L]...)
}

// Start starts given number of r/t message handlers in background,
// by default r/t = 1/1 (single-threaded, strictly ordered processing).
func (p *Pipe) Start() {
	if p.started.Swap(true) || p.stopped.Load() {
		return // already started or stopped
	}

	// apply opts
	opts := &p.Options
	p.apply(opts)

	// start R handlers
	for i := 0; i < opts.Rproc; i++ {
		p.rwg.Add(1)
		go p.R.Handler(&p.rwg)
	}
	go func() {
		p.rwg.Wait() // [1] after s.R.Input is closed (or no handlers)
		p.R.CloseOutput()
	}()

	// start L handlers
	for i := 0; i < opts.Lproc; i++ {
		p.lwg.Add(1)
		go p.L.Handler(&p.lwg)
	}
	go func() {
		p.lwg.Wait() // [1] after s.L.Input is closed (or no handlers)
		p.L.CloseOutput()
	}()

	// start the event handler
	p.evwg.Add(1)
	go p.eventHandler(&p.evwg)

	// stop everything if both directions finish
	go func() {
		p.lwg.Wait()
		p.rwg.Wait()
		p.Stop()
	}()

	// stop everything on context cancel
	go func() {
		<-p.ctx.Done()
		p.Stop()
	}()

	// publish the start event!
	go p.Event(EVENT_START, nil)
}

// alive is called whenever either direction gets a new KEEPALIVE message.
// alive emits EVENT_ESTABLISHED + fills p.Caps if enabled.
func (p *Pipe) alive(ev *Event) bool {
	// already seen KEEPALIVE in both directions?
	rstamp, lstamp := p.R.Alive.Load(), p.L.Alive.Load()
	if rstamp == 0 || lstamp == 0 {
		return true // not yet, keep trying
	}

	// seen OPEN for both directions?
	ropen, lopen := p.R.Open.Load(), p.L.Open.Load()
	if ropen == nil || lopen == nil {
		return true // strange, but keep trying
	}

	// find out common caps
	if p.Options.Caps {
		// collect common caps into common
		var common caps.Caps
		ropen.Caps.Each(func(i int, cc caps.Code, rcap caps.Cap) {
			// support on both ends?
			lcap := lopen.Caps.Get(cc)
			if lcap == nil {
				return
			}

			// needs an intersection?
			if icap := rcap.Intersect(lcap); icap != nil {
				common.Set(cc, icap) // use the new intersection value
			} else {
				common.Set(cc, rcap) // just reference the received
			}
		})

		// overwrite p.Caps
		p.Caps.Clear()
		p.Caps.SetFrom(common)
	}

	// announce the session is established
	p.Event(EVENT_ESTABLISHED, nil)

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

	// publish the event (ignore the global context)
	go p.event(&Event{Type: EVENT_STOP}, nil, false)

	// close all inputs
	p.L.CloseInput()
	p.R.CloseInput()

	// yank the cable out of blocked calls (hopefully)
	p.cancel()

	// wait for input handlers
	p.lwg.Wait()
	p.rwg.Wait()
	// NB: now [1] will close the R/L outputs

	// safely stop the event handler and wait for it to finish
	func() {
		defer func() { recover() }()
		close(p.events)
	}()
	p.evwg.Wait()
}

// Wait blocks until all handlers finish.
func (p *Pipe) Wait() {
	p.rwg.Wait()
	p.lwg.Wait()
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
	v := p.pool.Get()
	if v == nil {
		m = msg.NewMsg()
	} else {
		m = v.(*msg.Msg)
	}

	// add pipe context
	pc := PipeContext(m)
	pc.Pipe = p

	// prepare the upper layer?
	if len(typ) > 0 {
		m.SetUp(typ[0])
	}

	return m
}

// Put resets msg and returns it to pool, which might free it
func (p *Pipe) Put(m *msg.Msg) {
	// NOP
	if m == nil {
		return
	}

	// do not re-use?
	pc := PipeContext(m)
	if pc.Action.Is(ACTION_BORROW) {
		return
	}

	// re-use
	pc.Reset()
	m.Reset()
	p.pool.Put(m)
}
