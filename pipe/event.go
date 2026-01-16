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
	case <-ev.Pipe.Ctx.Done():
		return false
	case <-ev.done:
		return true
	}
}

// attachEvent initializes the event handler
func (p *Pipe) attachEvent() error {
	// p.events first pass: add non-wildcard handlers, collect wildcards
	var wildcards []*Handler
	for _, hd := range p.Options.Handlers {
		// is valid?
		if hd == nil || hd.Func == nil {
			continue
		} else if len(hd.Types) == 0 {
			wildcards = append(wildcards, hd)
			continue
		}

		// add to p.events
		types := slices.Clone(hd.Types)
		slices.Sort(types)
		for _, typ := range slices.Compact(types) {
			if typ == "*" {
				wildcards = append(wildcards, hd)
			} else {
				p.events[typ] = append(p.events[typ], hd)
			}
		}
	}

	// p.events second pass: add wildcards (avoid duplicates)
	for typ, hds := range p.events {
		for _, wh := range wildcards {
			if !slices.Contains(hds, wh) {
				hds = append(hds, wh)
			}
		}
		p.events[typ] = hds
	}
	p.events["*"] = wildcards

	// p.events final pass: sort all handlers
	for _, hds := range p.events {
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

	sent := p.sendEvent(ev, p.Ctx, false)
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
	ev.Seq = p.evseq.Add(1)

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
	ctx := p.Ctx
	if wg != nil {
		defer wg.Done()
	}

	for ev := range p.evch {
		// prepare the handlers
		hs := p.events[ev.Type]
		if len(hs) == 0 {
			hs = p.events["*"]
		}

		// call handlers
		for _, h := range hs {
			// skip handler?
			if h.Dir != 0 && h.Dir&ev.Dir == 0 {
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
			if ctx.Err() != nil {
				return // pipe is stopping
			} else if ev.Action.Has(ACTION_DROP | ACTION_ACCEPT) {
				break // skip other handlers
			}
		}

		// event is done
		if ev.done != nil {
			close(ev.done)
		}
	}
}
