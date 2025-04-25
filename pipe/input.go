package pipe

import (
	"io"
	"maps"
	"slices"
	"time"

	"github.com/bgpfix/bgpfix/afi"
	"github.com/bgpfix/bgpfix/attrs"
	"github.com/bgpfix/bgpfix/caps"
	"github.com/bgpfix/bgpfix/dir"
	"github.com/bgpfix/bgpfix/filter"
	"github.com/bgpfix/bgpfix/msg"
)

// Input processes incoming BGP messages through Callbacks
// and (optionally) writes the result to attached Line.
type Input struct {
	Pipe *Pipe // attached to this Pipe (nil before pipe start)
	Line *Line // attached to this Line (nil before pipe start)

	Id   int     // optional id
	Name string  // optional name
	Dir  dir.Dir // input direction

	// In is the input for incoming messages.
	In chan *msg.Msg

	// Reverse, when true, runs callbacks in reverse order.
	Reverse bool

	// CbFilter controls which callbacks to skip (disabled by default)
	CbFilter CbFilterMode

	// CbFilterValue specifies the value for CbFilter
	CbFilterValue any

	// Filter is an optional message filter for this Input
	Filter *filter.Filter

	ibuf []byte          // input buffer
	cbs  [16][]*Callback // callbacks for given message type
	done chan struct{}   // closed when the input is done processing
}

// attach attaches this Input to the given Pipe-Line.
func (in *Input) attach(p *Pipe, l *Line) error {
	in.Pipe = p
	in.Line = l
	in.Dir = l.Dir
	in.done = make(chan struct{})

	// copy relevant callbacks to cbs
	var cbs []*Callback
	for _, cb := range p.Options.Callbacks {
		// nil?
		if cb == nil || cb.Func == nil {
			continue
		}

		// direction match?
		if cb.Dir != 0 && cb.Dir&l.Dir == 0 {
			continue
		}

		// callback filter?
		if cbfilterSkip(in, cb) {
			continue
		}

		// take it
		cbs = append(cbs, cb)
	}

	// sort
	slices.SortStableFunc(cbs, func(a, b *Callback) int {
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
		if in.Reverse {
			return b.Order - a.Order
		} else {
			return a.Order - b.Order
		}
	})

	// reference in in.cbs[type]
	for _, cb := range cbs {
		// all types?
		if len(cb.Types) == 0 {
			for i := range in.cbs {
				in.cbs[i] = append(in.cbs[i], cb)
			}
			continue
		}

		// only select types
		types := slices.Clone(cb.Types)
		slices.Sort(types)
		for _, t := range slices.Compact(types) {
			if t < msg.Type(len(in.cbs)) {
				in.cbs[t] = append(in.cbs[t], cb)
			} else {
				in.cbs[0] = append(in.cbs[0], cb)
			}
		}
	}

	return nil
}

// prepare prepares metadata and context of m for processing in this Input.
// The message type must already be set.
func (in *Input) prepare(m *msg.Msg) *Context {
	mx := UseContext(m)

	// already mine?
	if mx.Input == in {
		return mx
	} else {
		mx.Pipe = in.Pipe
		mx.Input = in
	}

	// message metadata
	m.Dir = in.Dir
	if m.Seq == 0 {
		m.Seq = in.Line.seq.Add(1)
	}
	if m.Time.IsZero() {
		m.Time = time.Now().UTC()
	}

	// callbacks
	if mx.cbs == nil {
		if int(m.Type) < len(in.cbs) {
			mx.cbs = in.cbs[m.Type]
		} else {
			mx.cbs = in.cbs[0]
		}
	}

	return mx
}

func (in *Input) process() {
	var (
		p        = in.Pipe
		l        = in.Line
		closed   bool
		eor_todo map[afi.AS]bool
		eval     = filter.NewEval(true)
	)
	defer close(in.done)

input:
	for m := range in.In {
		// prepare tools
		mx := in.prepare(m)
		eval.SetMsg(m)
		eval.SetPipe(p.KV, p.Caps, mx.tags)

		// has input filter?
		if in.Filter != nil {
			// parse the message first?
			if m.Upper == msg.INVALID && p.ParseMsg(m) != nil {
				p.PutMsg(m)
				continue input
			}

			// evaluate the filter
			if !eval.Run(in.Filter) {
				p.PutMsg(m)
				continue input
			}
		}

		// run the callbacks
		for len(mx.cbs) > 0 {
			// eat the head
			cb := mx.cbs[0]
			mx.cbs = mx.cbs[1:]

			// skip callback?
			if cb.Dropped {
				continue // dropped
			} else if cb.Id != 0 && mx.Input.Id == cb.Id {
				continue // skip own messages
			} else if cb.Enabled != nil && !cb.Enabled.Load() {
				continue // disabled
			}

			// need to parse first?
			if m.Upper == msg.INVALID && (!cb.Raw || cb.Filter != nil) {
				if p.ParseMsg(m) != nil {
					p.PutMsg(m)
					continue input // parse error, drop the message
				}
			}

			// evaluate a message filter?
			if cb.Filter != nil && !eval.Run(cb.Filter) {
				continue // skip m for this callback
			}

			// run the callback, block until done
			mx.Callback = cb
			if !cb.Func(m) {
				mx.Action.Drop()
			}
			mx.Callback = nil

			// what's next?
			if mx.Action.IsDrop() {
				p.PutMsg(m)
				continue input // next message
			}
			if mx.Action.IsAccept() {
				break // take it as-is
			}
		}

		// m updates the UNIX timestamp for its type?
		t := m.Time.Unix()
		switch m.Type {
		case msg.OPEN:
			if m.Parse(p.Caps) != nil {
				break // not valid
			}

			oldt := l.LastOpen.Load()
			if t > oldt && l.LastOpen.CompareAndSwap(oldt, t) {
				mx.Action.Add(ACTION_BORROW)
				l.Open.Store(&m.Open)
				p.Event(EVENT_OPEN, m.Dir, t)
			}

		case msg.KEEPALIVE:
			oldt := l.LastAlive.Load()
			if t > oldt && l.LastAlive.CompareAndSwap(oldt, t) {
				p.Event(EVENT_ALIVE, m.Dir, t)
			}

		case msg.UPDATE:
			oldt := l.LastUpdate.Load()
			if t > oldt && l.LastUpdate.CompareAndSwap(oldt, t) {
				p.Event(EVENT_UPDATE, m.Dir, t)
			}

			// an End-of-RIB marker?
			if m.Len() < 32 && m.Parse(p.Caps) == nil {
				// get Address Family
				as := afi.AS_IPV4_UNICAST
				if m.Len() == msg.HEADLEN+msg.UPDATE_MINLEN {
					// must be IPv4 unicast
				} else if a := m.Update.Attrs; a.Len() != 1 {
					break // must have 1 attribute
				} else if unreach, ok := a.Get(attrs.ATTR_MP_UNREACH).(*attrs.MP); !ok {
					break // the attr must be ATTR_MP_UNREACH
				} else {
					as = unreach.AS
				}

				// already seen?
				if _, loaded := l.EoR.LoadOrStore(as, t); loaded {
					break
				} else { // it's new, announce
					p.Event(EVENT_EOR_AF, m.Dir, as.Afi(), as.Safi())
				}

				// tick afi off our todo list
				if eor_todo == nil {
					eor_todo = make(map[afi.AS]bool)
					if c, ok := p.Caps.Get(caps.CAP_MP).(*caps.MP); ok {
						maps.Copy(eor_todo, c.Proto)
					} else {
						eor_todo[afi.AS_IPV4_UNICAST] = true
					}
				} else if len(eor_todo) == 0 {
					break // already seen all required AFs
				}

				// satisfies all AFs in p.Caps?
				delete(eor_todo, as)
				if len(eor_todo) == 0 {
					p.Event(EVENT_EOR, m.Dir)
				}
			}
		}

		// output closed?
		if closed {
			p.PutMsg(m) // drop on the floor
		} else if l.WriteOutput(m) != nil {
			closed = true // start dropping from now on
		}
	}
}

// Close safely closes the .In channel, which should eventually stop the Input
func (in *Input) Close() {
	defer func() { recover() }()
	close(in.In)
}

// Wait blocks until the input is done processing the messages (returns true),
// or aborts if the Pipe context is cancelled (returns false).
func (in *Input) Wait() bool {
	select {
	case <-in.Pipe.ctx.Done():
		return false
	case <-in.done:
		return true
	}
}

// Write implements io.Writer and reads all BGP messages from src into in.In.
// Copies bytes from src. Consumes what it can, buffers the remainder if needed.
// Returns n equal to len(src). May block if pi.In is full.
//
// In case of a non-nil err, call Write(nil) to re-try using the buffered remainder,
// until it returns a nil err.
//
// Must not be used concurrently.
func (in *Input) Write(src []byte) (int, error) {
	return in.WriteFunc(src, nil)
}

// WriteFunc is the same as Input.Write(), but takes an optional callback function
// to be called just before the message is accepted for processing. If the callback
// returns false, the message is silently dropped instead.
func (in *Input) WriteFunc(src []byte, cb CallbackFunc) (int, error) {
	var (
		p   = in.Pipe
		now = time.Now().UTC()
	)

	// append src and switch to inbuf if needed
	raw := src
	if len(in.ibuf) > 0 {
		in.ibuf = append(in.ibuf, raw...)
		raw = in.ibuf // [1]
	}

	// check raw on return: leave the remainder at the start of d.inbuf?
	defer func() {
		if len(raw) == 0 {
			in.ibuf = in.ibuf[:0]
		} else if len(in.ibuf) == 0 || &raw[0] != &in.ibuf[0] { // NB: trick to avoid self-copy [1]
			in.ibuf = append(in.ibuf[:0], raw...)
		} // otherwise there is something left, but already @ s.inbuf[0:]
	}()

	// process until raw is empty
	for len(raw) > 0 {
		// grab memory and parse raw[:off]
		m := p.GetMsg()
		off, err := m.FromBytes(raw)
		switch err {
		case nil:
			raw = raw[off:]
		case io.ErrUnexpectedEOF: // need more data
			p.PutMsg(m)
			return len(src), nil // defer will buffer raw
		default: // parse error, try to skip the garbled data
			p.PutMsg(m)
			if off > 0 {
				raw = raw[off:] // buffer the remainder for re-try
			} else {
				raw = nil // no idea, throw out
			}
			return len(src), err
		}

		// prepare m
		m.Time = now
		if cb != nil && !cb(m) {
			p.PutMsg(m)
			continue
		}

		// send
		m.CopyData()
		if err := in.WriteMsg(m); err != nil {
			return len(src), err
		}
	}

	// exactly len(src) bytes consumed and processed, no error
	return len(src), nil
}

// WriteMsg safely sends m to in.In, avoiding a panic if it is closed.
// It assigns a sequence number and timestamp before writing to the channel.
func (in *Input) WriteMsg(m *msg.Msg) (write_error error) {
	// block the caller while we prepare the message
	in.prepare(m)

	// safe write to in.In
	defer func() {
		if recover() != nil {
			write_error = ErrInClosed
			in.Pipe.PutMsg(m)
		}
	}()
	in.In <- m

	return nil
}
