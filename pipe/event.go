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
	EVENT_PARSE_ERROR = "bgpfix/pipe.PARSE_ERROR"

	// OPEN made it to R, stored in pipe.R.Open
	EVENT_OPEN_R = "bgpfix/pipe.OPEN_R"

	// OPEN made it to L, stored in pipe.L.Open
	EVENT_OPEN_L = "bgpfix/pipe.OPEN_L"

	// session established = OPEN+KEEPALIVE made it to both sides
	EVENT_ESTABLISHED = "bgpfix/pipe.ESTABLISHED"

	// new KEEPALIVE timestamp in pipe.R
	EVENT_ALIVE_R = "bgpfix/pipe.ALIVE_R"

	// new KEEPALIVE timestamp in pipe.L
	EVENT_ALIVE_L = "bgpfix/pipe.ALIVE_L"
)

// Event represents an arbitrary event for a BGP pipe.
// Seq and Time will be set by the handler if non-zero.
type Event struct {
	Pipe *Pipe     `json:"-"`              // parent pipe
	Seq  uint64    `json:"seq,omitempty"`  // event sequence number
	Time time.Time `json:"time,omitempty"` // event timestamp

	Type  string   `json:"type"`  // type, usually "lib/pkg.NAME"
	Msg   *msg.Msg `json:"-"`     // optional message that caused the event
	Error error    `json:"err"`   // optional error value
	Value any      `json:"value"` // optional value, type-specific
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
		case p.events <- ev:
			return true
		default:
			return false
		}
	} else {
		select {
		case <-ctxchan:
			return false
		case p.events <- ev:
			return true
		}
	}
}

// Event announces a new event type et to the pipe, with optional message and arguments.
// Error arguments are joined together into ev.Err, the first non-error argument
// is used as ev.Val. Returns true iff the event was queued for processing.
func (p *Pipe) Event(et string, msg *msg.Msg, args ...any) (sent bool) {
	ev := &Event{Type: et}

	if msg != nil {
		PipeAction(msg).Set(ACTION_BORROW) // don't re-use mem [1]
		ev.Msg = msg
	}

	var errs []error
	for _, arg := range args {
		if err, ok := arg.(error); ok {
			errs = append(errs, err)
		} else if ev.Value == nil {
			ev.Value = arg
		}
	}
	switch len(errs) {
	case 0:
		ev.Error = nil
	case 1:
		ev.Error = errs[0]
	default:
		ev.Error = errors.Join(errs...)
	}

	return p.event(ev, p.ctx, false)
}

// eventHandler reads p.Events and broadcasts events to handlers
func (p *Pipe) eventHandler(wg *sync.WaitGroup) {
	if wg != nil {
		defer wg.Done()
	}

	var (
		seq  uint64
		opts = &p.Options
		wcbs = opts.Events[""] // wildcard handlers - for any event type
	)

	for ev := range p.events {
		// metadata
		if ev.Seq == 0 {
			seq++
			ev.Seq = seq
		}
		if ev.Time.IsZero() {
			ev.Time = time.Now().UTC()
		}

		// call handlers for ev.Type
		cbs := opts.Events[ev.Type]
		for i, cb := range cbs {
			if cb == nil {
				continue
			}
			if !cb(ev) {
				cbs[i] = nil
			}
		}

		// call wildcard handlers
		for i, cb := range wcbs {
			if cb == nil {
				continue
			}
			if !cb(ev) {
				wcbs[i] = nil
			}
		}

		// try to re-use (but see [1])
		if ev.Msg != nil {
			p.Put(ev.Msg)
		}
	}
}
