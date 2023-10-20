package pipe

import (
	"context"
	"errors"
	"sync"
	"time"

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
)

// Event represents an arbitrary event for a BGP pipe.
// Seq and Time will be set by the handler if non-zero.
type Event struct {
	Pipe *Pipe     `json:"-"`              // parent pipe
	Seq  uint64    `json:"seq,omitempty"`  // event sequence number
	Time time.Time `json:"time,omitempty"` // event timestamp

	Type  string   `json:"type"`  // type, usually "lib/pkg.NAME"
	Dst   msg.Dst  `json:"dst"`   // optional destination
	Msg   *msg.Msg `json:"-"`     // optional message that caused the event
	Error error    `json:"err"`   // optional error value
	Value any      `json:"value"` // optional value, type-specific
}

// String returns the event Type, or "(nil)" if ev is nil
func (ev *Event) String() string {
	if ev == nil {
		return "(nil)"
	} else {
		return ev.Type
	}
}

// Event announces a new event type et to the pipe, with optional arguments.
// The first msg.Dst argument is used as ev.Dst.
// The first *msg.Msg is used as ev.Msg and borrowed (add ACTION_BORROW).
// All error arguments are joined together into single ev.Error.
// The remaining arguments are used as ev.Val.
// Returns true iff the event was queued for processing.
func (p *Pipe) Event(et string, args ...any) (sent bool) {
	ev := &Event{Type: et}

	// process args
	var errs []error
	var vals []any
	var dst_set, msg_set bool
	for _, arg := range args {
		if m, ok := arg.(*msg.Msg); ok && !msg_set {
			Context(m).Action.Add(ACTION_BORROW) // make m safe to reference for later use
			ev.Msg = m
			msg_set = true
		} else if d, ok := arg.(msg.Dst); ok && !dst_set {
			ev.Dst = d
			dst_set = true
		} else if err, ok := arg.(error); ok {
			errs = append(errs, err)
		} else {
			vals = append(vals, arg)
		}
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
	switch len(vals) {
	case 0:
		ev.Value = nil
	case 1:
		ev.Value = vals[0]
	case 2:
		ev.Value = vals
	}

	return p.event(ev, p.ctx, false)
}

// event sends ev with given ctx; if noblock is true, it never blocks on full channel
func (p *Pipe) event(ev *Event, ctx context.Context, noblock bool) (sent bool) {
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

		// call handlers for ev.Type
		hs := p.events[ev.Type]
		for _, h := range hs {
			if h == nil || h.Func == nil {
				continue // dropped [2]
			}
			if h.Enabled != nil && !h.Enabled.Load() {
				continue // disabled
			}
			if h.Dst != 0 && h.Dst != ev.Dst {
				continue // different direction
			}
			if !h.Func(ev) {
				h.Func = nil // drop [2]
			}
		}

		// call wildcard handlers
		for _, h := range whs {
			if h == nil || h.Func == nil {
				continue // dropped [3]
			}
			if h.Enabled != nil && !h.Enabled.Load() {
				continue // disabled
			}
			if h.Dst != 0 && h.Dst != ev.Dst {
				continue // different direction
			}
			if !h.Func(ev) {
				h.Func = nil // drop [3]
			}
		}
	}
}
