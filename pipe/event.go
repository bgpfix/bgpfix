package pipe

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/bgpfix/bgpfix/dir"
	"github.com/bgpfix/bgpfix/msg"
)

// a collection of events generated internally by pipe
var (
	// pipe has finished starting
	EVENT_START = "bgpfix/pipe.START"

	// pipe is about to stop
	EVENT_STOP = "bgpfix/pipe.STOP"

	// could not parse the message before its callback
	EVENT_PARSE = "bgpfix/pipe.PARSE"

	// valid OPEN with a bigger message timestamp (seconds) made it to output
	EVENT_OPEN = "bgpfix/pipe.OPEN"

	// KEEPALIVE with a bigger message timestamp (seconds) made it to output
	EVENT_ALIVE = "bgpfix/pipe.ALIVE"

	// UPDATE with a bigger message timestamp (seconds) made it to output
	EVENT_UPDATE = "bgpfix/pipe.UPDATE"

	// session established (OPEN+KEEPALIVE made it to both sides)
	EVENT_ESTABLISHED = "bgpfix/pipe.ESTABLISHED"

	// End-of-RIB for new AF made it to output in given direction
	EVENT_EOR_AF = "bgpfix/pipe.EOR_AF"

	// End-of-RIB for all AFs in Caps made it to output in given direction
	EVENT_EOR = "bgpfix/pipe.EOR"
)

// Event represents an arbitrary event for a BGP pipe.
// Seq and Time will be set by the handler if non-zero.
type Event struct {
	Pipe *Pipe     `json:"-"`              // parent pipe
	Seq  uint64    `json:"seq,omitempty"`  // event sequence number
	Time time.Time `json:"time,omitempty"` // event timestamp

	Type  string  `json:"type"`  // type, usually "lib/pkg.NAME"
	Dir   dir.Dir `json:"dir"`   // optional event direction
	Msg   string  `json:"msg"`   // optional BGP message in JSON
	Error error   `json:"err"`   // optional error related to the event
	Value any     `json:"value"` // optional value, type-specific

	Handler *Handler      // currently running handler (may be nil)
	Action  Action        // optional event action (zero means none)
	done    chan struct{} // closed when all handlers are done
}

// String returns event type and seq number as string
func (ev *Event) String() string {
	if ev == nil {
		return "nil"
	} else {
		return fmt.Sprintf("E%d:%s", ev.Seq, ev.Type)
	}
}

// Wait blocks until the event is handled (returns true),
// or aborts if the Pipe context is cancelled (returns false).
func (ev *Event) Wait() bool {
	select {
	case <-ev.Pipe.ctx.Done():
		return false
	case <-ev.done:
		return true
	}
}

// attachEvent initializes the event handler
func (p *Pipe) attachEvent() error {
	// copy valid handlers to hds
	var hds []*Handler
	for _, hd := range p.Options.Handlers {
		if hd != nil && hd.Func != nil {
			hds = append(hds, hd)
		}
	}

	// sort hds
	slices.SortStableFunc(hds, func(a, b *Handler) int {
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

	// rewrite event handlers to p.events
	for _, h := range hds {
		types := slices.Clone(h.Types)
		slices.Sort(types)
		for _, typ := range slices.Compact(types) {
			p.events[typ] = append(p.events[typ], h)
		}
	}

	return nil
}

// Event announces a new event type et to the pipe, with optional arguments.
// The first dir.Dir argument is used as ev.Dir.
// The first *msg.Msg is used as ev.Msg and borrowed (add ACTION_BORROW).
// All error arguments are joined together into a single ev.Error.
// The remaining arguments are used as ev.Val.
func (p *Pipe) Event(et string, args ...any) *Event {
	ev := &Event{
		Type: et,
		done: make(chan struct{}),
	}

	// process args
	var errs []error
	var vals []any
	var dir_set, msg_set bool
	for _, arg := range args {
		switch v := arg.(type) {
		case *msg.Msg:
			if !msg_set {
				ev.Msg = v.String()
				msg_set = true
				continue
			}
		case dir.Dir:
			if !dir_set {
				ev.Dir = v
				dir_set = true
				continue
			}
		case error:
			errs = append(errs, v)
			continue
		}
		// ...and if nothing worked:
		vals = append(vals, arg)
	}

	// set error
	switch len(errs) {
	case 0:
		ev.Error = nil
	case 1:
		ev.Error = errs[0]
	default:
		ev.Error = errors.Join(errs...)
	}

	// set value
	if len(vals) > 0 {
		ev.Value = vals
	}

	sent := p.sendEvent(ev, p.ctx, false)
	if !sent {
		close(ev.done)
	}

	return ev
}

// sendEvent sends ev with given ctx; if noblock is true, it never blocks on full channel
func (p *Pipe) sendEvent(ev *Event, ctx context.Context, noblock bool) (sent bool) {
	defer func() { recover() }() // in case of closed p.events

	ev.Pipe = p
	ev.Time = time.Now().UTC()

	var ctxchan <-chan struct{}
	if ctx != nil {
		ctxchan = ctx.Done()
	}

	if noblock {
		select {
		case <-ctxchan:
			return false
		case p.evch <- ev:
			return true
		default:
			return false
		}
	} else {
		select {
		case <-ctxchan:
			return false
		case p.evch <- ev:
			return true
		}
	}
}

// eventHandler reads p.evch and broadcasts events to handlers
func (p *Pipe) eventHandler(wg *sync.WaitGroup) {
	if wg != nil {
		defer wg.Done()
	}

	var (
		seq uint64
		hs  []*Handler      // handlers to run for given event
		whs = p.events["*"] // wildcard handlers - for any event type
	)

	for ev := range p.evch {
		// metadata
		if ev.Seq == 0 {
			seq++
			ev.Seq = seq
		}
		if ev.Time.IsZero() {
			ev.Time = time.Now().UTC()
		}

		// prepare the handlers
		hs = append(hs[:0], p.events[ev.Type]...) // TODO: append whs to p.events before?
		hs = append(hs, whs...)

		// call handlers
		for _, h := range hs {
			// skip handler?
			if h == nil || h.Dropped {
				continue // dropped
			} else if h.Dir != 0 && h.Dir&ev.Dir == 0 {
				continue // different direction
			} else if h.Enabled != nil && !h.Enabled.Load() {
				continue // disabled
			}

			// run the handler, block until done
			ev.Handler = h
			if !h.Func(ev) {
				h.Drop()
			}
			ev.Handler = nil

			// what's next?
			if ev.Action&(ACTION_DROP|ACTION_ACCEPT) != 0 {
				break // skip other handlers
			}
		}

		// event is done
		if ev.done != nil {
			close(ev.done)
		}
	}
}
