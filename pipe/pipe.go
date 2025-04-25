// Package pipe provides BGP message processing with callbacks.
package pipe

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bgpfix/bgpfix/caps"
	"github.com/bgpfix/bgpfix/dir"
	"github.com/bgpfix/bgpfix/msg"
	"github.com/puzpuzpuz/xsync/v3"
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

	Options           // pipe options; modify before Start()
	Caps    caps.Caps // BGP capability context; always thread-safe
	L       *Line     // line processing messages from R to L
	R       *Line     // line processing messages from L to R

	// generic Key-Value store, always thread-safe
	KV *xsync.MapOf[string, any]

	ctx    context.Context         // parent context for all children
	cancel context.CancelCauseFunc // cancels ctx

	started atomic.Bool    // true iff Start() called
	stopped atomic.Bool    // true iff Stop() called
	wgstart sync.WaitGroup // 1 before start, 0 after start

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
	p.KV = xsync.NewMapOf[string, any]()

	p.R = &Line{
		Pipe: p,
		Dir:  dir.DIR_R,
		Input: Input{
			In: make(chan *msg.Msg, 10),
		},
		Out: make(chan *msg.Msg, 10),
	}

	p.L = &Line{
		Pipe: p,
		Dir:  dir.DIR_L,
		Input: Input{
			In: make(chan *msg.Msg, 10),
		},
		Out: make(chan *msg.Msg, 10),
	}

	// NB: add internal handlers
	p.events = map[string][]*Handler{
		EVENT_ALIVE: {&Handler{
			Func: p.checkEstablished,
		}},
	}
	p.evch = make(chan *Event, 10)

	p.wgstart.Add(1)
	return p
}

func (p *Pipe) attach() error {
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

	// attach Inputs to Lines
	if err := p.L.attach(); err != nil {
		return err
	}
	if err := p.R.attach(); err != nil {
		return err
	}

	// attach Event handler
	return p.attachEvent()
}

// checkEstablished is called whenever either direction gets a new KEEPALIVE message,
// until it emits EVENT_ESTABLISHED and unregisters. Fills p.Caps if enabled.
func (p *Pipe) checkEstablished(ev *Event) bool {
	// already seen KEEPALIVE in both directions?
	rstamp, lstamp := p.R.LastAlive.Load(), p.L.LastAlive.Load()
	if rstamp == 0 || lstamp == 0 {
		return true // not yet, keep trying
	}

	// seen OPEN in both directions?
	ropen, lopen := p.R.Open.Load(), p.L.Open.Load()
	if ropen == nil || lopen == nil {
		return true // strange, but keep trying
	}

	// find out common caps?
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
		p.Info().Bytes("caps", p.Caps.ToJSON(nil)).Msg("negotiated session capabilities")
	}

	// announce that the session is established
	p.Event(EVENT_ESTABLISHED, max(rstamp, lstamp))

	// no more calls to this callback
	return false
}

// Start starts the Pipe in background and returns.
func (p *Pipe) Start() error {
	if p.started.Swap(true) {
		return ErrStarted // already started
	} else if p.stopped.Load() {
		return ErrStopped // already stopped
	}

	// apply options
	if err := p.attach(); err != nil {
		return err
	}

	// start line inputs
	p.L.start()
	p.R.start()

	// stop the pipe when both lines finish
	go func() {
		p.L.Wait()
		p.R.Wait()
		p.Stop()
	}()

	// start the event handler
	p.evwg.Add(1)
	go p.eventHandler(&p.evwg)

	// stop the pipe on context cancel
	go func() {
		<-p.ctx.Done()
		p.Stop()
	}()

	// publish the start event!
	go p.Event(EVENT_START)
	p.wgstart.Done()
	return nil
}

// Stop stops all inputs and blocks till they finish processing.
// Pipe must not be used again past this point.
// Closes all inputs, which should eventually close all outputs,
// possibly after this function returns.
func (p *Pipe) Stop() {
	if p.stopped.Swap(true) || !p.started.Load() {
		return // already stopped, or not started yet
	}

	// publish the event (ignore the global context)
	go p.sendEvent(&Event{Type: EVENT_STOP}, nil, false)

	// close all inputs (if not done already)
	p.L.Close()
	p.R.Close()

	// yank the cable out of blocked calls (give it 1 sec)
	go func() {
		<-time.After(time.Second)
		p.cancel(ErrStopped)
	}()

	// wait for input handlers
	p.L.Wait()
	p.R.Wait()

	// stop the event handler and wait for it to finish
	close(p.evch)
	p.evwg.Wait()
}

// Wait blocks until the pipe starts and stops completely.
func (p *Pipe) Wait() {
	p.wgstart.Wait()
	p.L.Wait()
	p.R.Wait()
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

// GetMsg returns empty msg from pool, or a new msg object
func (p *Pipe) GetMsg() (m *msg.Msg) {
	if m, ok := p.msgpool.Get().(*msg.Msg); ok {
		return m
	} else {
		m = msg.NewMsg() // allocate
		UseContext(m)    // add context
		return m
	}
}

// PutMsg resets msg and returns it to pool, which might free it
func (p *Pipe) PutMsg(m *msg.Msg) {
	// NOP
	if m == nil {
		return
	}

	// do not re-use?
	mx := UseContext(m)
	if mx.Action.Is(ACTION_BORROW) {
		return
	}

	// re-cycle
	mx.Reset()
	m.Reset()
	p.msgpool.Put(m)
}

// ParseMsg parses given message m (if needed), in the context of this Pipe.
// In case of error, it emits EVENT_PARSE before returning.
func (p *Pipe) ParseMsg(m *msg.Msg) error {
	err := m.Parse(p.Caps)
	if err != nil {
		p.Event(EVENT_PARSE, m.Dir, m, err)
	}
	return err
}

// LineFor returns the line processing messages destined for dst.
// Returns p.R if dst is bidir (DST_LR).
func (p *Pipe) LineFor(dst dir.Dir) *Line {
	if dst == dir.DIR_L {
		return p.L
	} else {
		return p.R
	}
}
