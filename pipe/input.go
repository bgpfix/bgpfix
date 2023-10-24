package pipe

import (
	"io"
	"slices"
	"sync"
	"time"

	"github.com/bgpfix/bgpfix/msg"
)

// Input processes incoming BGP messages through Callbacks.
type Input struct {
	Pipe *Pipe // parent pipe
	Line *Line // parent line

	Name string  // optional name
	Dst  msg.Dst // line direction

	// In is the input, where to read incoming messages from.
	In chan *msg.Msg

	// Reverse, when true, runs callbacks in reverse order.
	Reverse bool

	// CallbackFilter controls which callbacks to skip (disabled by default)
	CallbackFilter FilterMode

	// FilterValue specifies the value for CallbackFilter
	FilterValue any

	// statistics
	Stats struct {
		Parsed  uint64
		Short   uint64
		Garbled uint64
	}

	ibuf []byte          // input buffer
	cbs  [16][]*Callback // callbacks for given message type
}

func (li *Input) attach(p *Pipe, l *Line) {
	li.Pipe = p
	li.Line = l

	// copy all callbacks to cbs
	var cbs []*Callback
	cbs = append(cbs, p.cbs...)
	if li.Reverse {
		slices.Reverse(cbs)
	}

	// reference only the relevant callbacks in li.cbs
	for _, cb := range cbs {
		// dst match?
		if cb.Dst != 0 && cb.Dst != l.Dst {
			continue
		}

		// callback filter?
		if filterSkip(li, cb) {
			continue
		}

		// message types?
		var types []msg.Type
		if len(cb.Types) == 0 {
			for i := 1; i < len(li.cbs); i++ {
				types = append(types, msg.Type(i))
			}
		} else {
			types = append(types, cb.Types...)
			slices.Sort(types)
			types = slices.Compact(types)
		}

		// reference relevant callbacks
		for _, t := range types {
			if t < msg.Type(len(li.cbs)) {
				li.cbs[t] = append(li.cbs[t], cb)
			} else {
				li.cbs[0] = append(li.cbs[0], cb)
			}
		}
	}
}

// prepare prepares metadata and context of m for processing in this Line.
// The message type must already be set.
func (pi *Input) prepare(m *msg.Msg) (pc *PipeContext) {
	// already prepared?
	pc = Context(m)
	if pc.Input == pi {
		return
	}
	pc.Input = pi

	// message metadata
	m.Dst = pi.Dst
	if m.Seq == 0 {
		m.Seq = pi.Line.seq.Add(1)
	}
	if m.Time.IsZero() {
		m.Time = time.Now().UTC()
	}

	// callbacks
	if pc.cbs == nil {
		if int(m.Type) < len(pi.cbs) {
			pc.cbs = pi.cbs[m.Type]
		} else {
			pc.cbs = pi.cbs[0]
		}
	}

	return
}

func (pi *Input) process(wg *sync.WaitGroup) {
	var (
		p      = pi.Pipe
		l      = pi.Line
		closed bool
	)

	if wg != nil {
		defer wg.Done()
	}

input:
	for m := range pi.In {
		// get context, clear actions except for BORROW
		pc := pi.prepare(m)
		pc.Action.Clear()

		// run the callbacks
		for len(pc.cbs) > 0 {
			// eat first callback
			cb := pc.cbs[0]
			pc.cbs = pc.cbs[1:]

			// disabled?
			if cb.Enabled != nil && !cb.Enabled.Load() {
				continue
			}

			// need to parse first?
			if !cb.Raw && m.Upper == msg.INVALID {
				if err := m.ParseUpper(p.Caps); err != nil {
					p.Event(EVENT_PARSE, pi.Dst, m, err)
					continue input // next message
				}
			}

			// run and wait
			pc.Callback = cb
			pc.Action |= cb.Func(m)
			pc.Callback = nil

			// what's next?
			if pc.Action.Is(ACTION_DROP) {
				p.Put(m)
				continue input // next message
			} else if pc.Action.Is(ACTION_ACCEPT) {
				break // take it as-is
			}
		}

		// m updates the UNIX timestamp for its type?
		t := m.Time.Unix()
		switch m.Type {
		case msg.OPEN:
			if m.ParseUpper(p.Caps) != nil {
				break // not valid
			}

			oldt := l.LastOpen.Load()
			if t > oldt && l.LastOpen.CompareAndSwap(oldt, t) {
				Context(m).Action.Add(ACTION_BORROW)
				l.Open.Store(&m.Open)
				p.Event(EVENT_OPEN, m.Dst, t, oldt)
			}

		case msg.KEEPALIVE:
			oldt := l.LastAlive.Load()
			if t > oldt && l.LastAlive.CompareAndSwap(oldt, t) {
				p.Event(EVENT_ALIVE, m.Dst, t, oldt)
			}

		case msg.UPDATE:
			oldt := l.LastUpdate.Load()
			if t > oldt && l.LastUpdate.CompareAndSwap(oldt, t) {
				p.Event(EVENT_UPDATE, m.Dst, t, oldt)
			}
		}

		// output closed?
		if closed {
			p.Put(m) // drop on the floor
		} else if l.WriteOut(m) != nil {
			closed = true // start dropping from now on
		}
	}
}

// Close safely closes the .In channel, which should eventually stop the Input
func (li *Input) Close() {
	defer func() { recover() }()
	close(li.In)
}

// WriteMsg safely sends m to pi.In, avoiding a panic if pi.In is closed.
// It assigns a sequence number and timestamp before writing to the channel.
func (pi *Input) WriteMsg(m *msg.Msg) (write_error error) {
	pi.prepare(m)
	defer func() {
		if recover() != nil {
			write_error = ErrInClosed
			pi.Pipe.Put(m)
		}
	}()
	pi.In <- m
	return nil
}

// Write implements io.Writer and reads all BGP messages from src into pi.In.
// Copies bytes from src. Consumes what it can, buffers the remainder if needed.
// Returns n equal to len(src). May block if pi.In is full.
//
// In case of a non-nil err, call Write(nil) to re-try using the buffered remainder,
// until it returns a nil err.
//
// Must not be used concurrently.
func (pi *Input) Write(src []byte) (n int, err error) {
	var (
		p   = pi.Pipe
		ss  = &pi.Stats
		now = time.Now().UTC()
	)

	// append src and switch to inbuf if needed
	n = len(src) // NB: always return n=len(src)
	raw := src
	if len(pi.ibuf) > 0 {
		pi.ibuf = append(pi.ibuf, raw...)
		raw = pi.ibuf // [1]
	}

	// on return, leave the remainder at the start of d.inbuf?
	defer func() {
		if len(raw) == 0 {
			pi.ibuf = pi.ibuf[:0]
		} else if len(pi.ibuf) == 0 || &raw[0] != &pi.ibuf[0] { // NB: trick to avoid self-copy [1]
			pi.ibuf = append(pi.ibuf[:0], raw...)
		} // otherwise there is something left, but already @ s.inbuf[0:]
	}()

	// process until raw is empty
	for len(raw) > 0 {
		// grab memory, parse raw, take mem reference
		m := p.Get()
		off, perr := m.Parse(raw)

		// success?
		switch perr {
		case nil:
			ss.Parsed++
			raw = raw[off:]
		case io.ErrUnexpectedEOF: // need more data
			ss.Short++
			return n, nil // defer will buffer raw
		default: // parse error, try to skip the garbled data
			ss.Garbled++
			if off > 0 {
				raw = raw[off:] // buffer the remainder for re-try
			} else {
				raw = nil // no idea, throw out
			}
			return n, perr
		}

		// prepare m
		m.Time = now
		m.CopyData()

		// send
		if err := pi.WriteMsg(m); err != nil {
			return n, err
		}
	}

	// exactly len(src) bytes consumed and processed, no error
	return n, nil
}
