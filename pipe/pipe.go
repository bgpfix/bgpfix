// Package pipe provides BGP message processing with callbacks.
package pipe

import (
	"context"
	"slices"
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
// allowing for building callback-based pipelines, with an internal
// event system.
//
// Use NewPipe() to get a new object and modify its Pipe.Options.
// Then call Pipe.Start() to start the message flow.
type Pipe struct {
	*zerolog.Logger

	Options Options   // pipe options; modify before Start()
	Caps    caps.Caps // BGP capability context; always thread-safe
	L       *Line     // L pipeline
	R       *Line     // R pipeline

	// generic Key-Value store, always thread-safe
	KV *xsync.MapOf[string, any]

	ctx    context.Context         // parent context for all children
	cancel context.CancelCauseFunc // cancels ctx

	started atomic.Bool    // true iff Start() called
	stopped atomic.Bool    // true iff Stop() called
	wgstart sync.WaitGroup // 1 before start, 0 after start

	cbs []*Callback // sorted callbacks
	hds []*Handler  // sorted handlers

	evch   chan *Event           // pipe event input
	evwg   sync.WaitGroup        // event handler routine
	events map[string][]*Handler // maps events to their handlers

	msgpool *sync.Pool // pool for new messages
}

// NewPipe returns a new pipe, which can be configured through its Options.
// To start/stop the pipe, call Start() and Stop().
func NewPipe(ctx context.Context) *Pipe {
	p := &Pipe{}
	p.ctx, p.cancel = context.WithCancelCause(ctx)

	p.Options = DefaultOptions

	p.Caps.Init() // NB: make it thread-safe
	p.KV = xsync.NewMapOf[any]()

	p.evch = make(chan *Event, 10)
	p.events = make(map[string][]*Handler)

	p.R = &Line{
		Pipe: p,
		Dst:  msg.DST_R,
		Out:  make(chan *msg.Msg, 10),
	}
	p.L = &Line{
		Pipe: p,
		Dst:  msg.DST_L,
		Out:  make(chan *msg.Msg, 10),
	}

	p.wgstart.Add(1)

	return p
}

func (p *Pipe) attach() {
	opts := &p.Options

	if opts.Logger != nil {
		p.Logger = opts.Logger
	} else {
		l := zerolog.Nop()
		p.Logger = &l
	}
	p.Logger = opts.Logger

	if opts.MsgPool != nil {
		p.msgpool = opts.MsgPool
	} else {
		p.msgpool = new(sync.Pool)
	}

	// sort valid callbacks to p.cbs
	for _, cb := range opts.Callbacks {
		if cb != nil && cb.Func != nil {
			p.cbs = append(p.cbs, cb)
		}
	}
	slices.SortStableFunc(p.cbs, func(a, b *Callback) int {
		if a.Pre != b.Pre {
			if a.Pre {
				return -1
			} else {
				return 1
			}
		}
		if a.Post != b.Post {
			if a.Post {
				return 1
			} else {
				return -1
			}
		}
		return a.Order - b.Order
	})

	// sort valid handlers to p.hds
	for _, hd := range opts.Handlers {
		if hd != nil && hd.Func != nil {
			p.hds = append(p.hds, hd)
		}
	}
	slices.SortStableFunc(p.hds, func(a, b *Handler) int {
		if a.Pre != b.Pre {
			if a.Pre {
				return -1
			} else {
				return 1
			}
		}
		if a.Post != b.Post {
			if a.Post {
				return 1
			} else {
				return -1
			}
		}
		return a.Order - b.Order
	})

	// register the very first EVENT_ALIVE handler
	p.events[EVENT_ALIVE] = append(p.events[EVENT_ALIVE], &Handler{
		Func: p.onAlive,
	})

	// rewrite event handlers to p.events
	for _, h := range p.hds {
		if h == nil || h.Func == nil {
			return
		}
		sort.Strings(h.Types)
		for _, typ := range slices.Compact(h.Types) {
			p.events[typ] = append(p.events[typ], h)
		}
	}

	// attach Inputs to Lines
	p.L.attach()
	p.R.attach()
}

// onAlive is called whenever either direction gets a new KEEPALIVE message,
// until it emits EVENT_ESTABLISHED and unregisters. Fills p.Caps if enabled.
func (p *Pipe) onAlive(ev *Event) bool {
	// already seen KEEPALIVE in both directions?
	rstamp, lstamp := p.R.LastAlive.Load(), p.L.LastAlive.Load()
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

// Start starts given number of r/t message handlers in background,
// by default r/t = 1/1 (single-threaded, strictly ordered processing).
func (p *Pipe) Start() {
	if p.started.Swap(true) || p.stopped.Load() {
		return // already started or stopped
	}

	// apply options
	p.attach()

	// start line inputs
	p.L.StartInputs()
	p.R.StartInputs()

	// wait for L, R, and both to finish
	go func() {
		p.L.WaitInputs()
		p.L.CloseOutput()
	}()
	go func() {
		p.R.WaitInputs()
		p.R.CloseOutput()
	}()
	go func() {
		p.L.WaitInputs()
		p.R.WaitInputs()
		p.Stop()
	}()

	// start the event handler
	p.evwg.Add(1)
	go p.eventHandler(&p.evwg)

	// stop everything on context cancel
	go func() {
		<-p.ctx.Done()
		p.Stop()
	}()

	// publish the start event!
	go p.Event(EVENT_START, nil)
	p.wgstart.Done()
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

	// close all inputs (if not done already)
	p.L.CloseInputs()
	p.R.CloseInputs()

	// yank the cable out of blocked calls (hopefully)
	p.cancel(ErrStopped)

	// wait for input handlers
	p.L.WaitInputs()
	p.R.WaitInputs()

	// stop the event handler and wait for it to finish
	close(p.evch)
	p.evwg.Wait()
}

// Wait blocks until the pipe starts and stops completely.
func (p *Pipe) Wait() {
	p.wgstart.Wait()
	p.L.WaitInputs()
	p.R.WaitInputs()
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
func (p *Pipe) Get() (m *msg.Msg) {
	if m, ok := p.msgpool.Get().(*msg.Msg); ok {
		return m
	} else {
		return msg.NewMsg()
	}
}

// Put resets msg and returns it to pool, which might free it
func (p *Pipe) Put(m *msg.Msg) {
	// NOP
	if m == nil {
		return
	}

	// do not re-use?
	pc := Context(m)
	if pc.Action.Is(ACTION_BORROW) {
		return
	}

	// re-use
	pc.Reset()
	m.Reset()
	p.msgpool.Put(m)
}

// LineTo returns the line processing messages destined from dst
func (p *Pipe) LineTo(dst msg.Dst) *Line {
	if dst == msg.DST_L {
		return p.L
	} else {
		return p.R
	}
}

// LineFrom returns the line processing messages coming from dst
func (p *Pipe) LineFrom(dst msg.Dst) *Line {
	if dst == msg.DST_L {
		return p.R
	} else {
		return p.L
	}
}
