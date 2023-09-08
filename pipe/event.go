package pipe

import (
	"sync"
	"time"

	"github.com/bgpfix/bgpfix/msg"
)

// a collection of events generated internally by pipe
var (
	EVENT_START = &EventType{
		Name:  "pipe/START",
		Descr: "pipe finished starting",
	}
	EVENT_STOP = &EventType{
		Name:  "pipe/STOP",
		Descr: "pipe is about to stop",
	}
	EVENT_PARSE = &EventType{
		Name:  "pipe/PARSE",
		Descr: "could not parse the message before its callback",
		Value: "the error message",
	}
	EVENT_R_OPEN = &EventType{
		Name:  "pipe/R_OPEN",
		Descr: "OPEN seen on R direction",
	}
	EVENT_L_OPEN = &EventType{
		Name:  "pipe/L_OPEN",
		Descr: "OPEN seen on L direction",
	}
	EVENT_OPEN = &EventType{
		Name:  "pipe/OPEN",
		Descr: "OPEN messages seen in both directions",
		// now both pipe.R.Open and pipe.L.Open are available
	}
)

// Event represents an arbitrary event for a BGP pipe.
// Seq and Time will be set by the handler if non-zero.
type Event struct {
	// optional metadata
	Seq  uint64    `json:"seq,omitempty"`  // event sequence number
	Time time.Time `json:"time,omitempty"` // event timestamp
	Msg  *msg.Msg  `json:"-"`              // message that caused the event

	// event details
	Type  any `json:"type"`  // type, usually a *reference* to a pkg variable
	Value any `json:"value"` // value, type-specific, may be nil
}

// EventType is the recommended - but not required - type to use for events
type EventType struct {
	Name  string `json:"name,omitempty"`  // event name, eg. "pkg/NAME"
	Descr string `json:"descr,omitempty"` // event description
	Value string `json:"value,omitempty"` // what's in the value?
}

// Event announces a new event type et to the pipe, with an optional value
func (p *Pipe) Event(et any, msg *msg.Msg, val ...any) {
	defer func() { recover() }() // in case of closed p.Events

	ev := &Event{
		Time: time.Now().UTC(),
		Msg:  msg,
		Type: et,
	}

	// make sure the message isn't re-used before event handlers finish [1]
	if msg != nil {
		msg.Action |= ACTION_KEEP
	}

	if len(val) > 0 {
		ev.Value = val[0]
	}

	select {
	case <-p.ctx.Done():
		// context cancelled
	case p.Events <- ev:
		// success
	}
}

// eventHandler reads p.Events and broadcasts events to handlers
func (p *Pipe) eventHandler(wg *sync.WaitGroup) {
	if wg != nil {
		defer wg.Done()
	}

	var (
		seq  uint64
		opts = &p.Options
		wcbs = opts.Events[nil] // wildcard handlers - for any event type
	)

	for ev := range p.Events {
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
			if !cb(p, ev) {
				cbs[i] = nil
			}
		}

		// call wildcard handlers
		for i, cb := range wcbs {
			if cb == nil {
				continue
			}
			if !cb(p, ev) {
				wcbs[i] = nil
			}
		}

		// try to re-use (but see [1])
		if ev.Msg != nil {
			p.Put(ev.Msg)
		}
	}
}
