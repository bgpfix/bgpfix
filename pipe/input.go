package pipe

import (
	"io"
	"slices"
	"time"

	"github.com/bgpfix/bgpfix/afi"
	"github.com/bgpfix/bgpfix/attrs"
	"github.com/bgpfix/bgpfix/caps"
	"github.com/bgpfix/bgpfix/dir"
	"github.com/bgpfix/bgpfix/filter"
	"github.com/bgpfix/bgpfix/msg"
	"golang.org/x/time/rate"
)

// Input processes incoming BGP messages (in given direction)
// through many Callbacks and optionally writes the result to attached Line.
type Input struct {
	Pipe *Pipe // attached to this Pipe (nil before pipe start)
	Line *Line // attached to this Line (nil before pipe start)

	Id   int     // optional input id
	Name string  // optional input name
	Dir  dir.Dir // input direction

	In            chan *msg.Msg    // input channel for incoming messages
	Reverse       bool             // if true, run callbacks in reverse order
	CbFilter      CbFilterMode     // which callbacks to skip? (disabled by default)
	CbFilterValue any              // optionally specifies the value for CbFilter
	Filter        []*filter.Filter // drop messages not matching all filters
	LimitRate     *rate.Limiter    // optional input rate limit (nil = no limit)
	LimitSkip     bool             // if true, drop messages over the LimitRate (instead delay)

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
		p           = in.Pipe
		ctx         = p.Ctx
		l           = in.Line
		closed      bool
		eval        = filter.NewEval(true)
		last_update int64
		eor_done    bool
		eor_todo    int
	)
	defer close(in.done)

input:
	for m := range in.In {
		// prepare tools
		mx := in.prepare(m)
		eval.SetMsg(m)
		eval.SetPipe(p.KV, p.Caps, mx.tags)

		// has input filter?
		if len(in.Filter) > 0 {
			// parse the message first?
			if m.Upper == msg.INVALID && p.ParseMsg(m) != nil {
				p.PutMsg(m)
				continue input
			}

			// evaluate the filters
			for _, f := range in.Filter {
				if !eval.Run(f) {
					p.PutMsg(m)
					continue input
				}
			}
		}

		// input rate limiter?
		if in.LimitRate != nil {
			if in.LimitSkip {
				if !in.LimitRate.Allow() {
					p.PutMsg(m)
					continue input
				}
			} else {
				if err := in.LimitRate.Wait(p.Ctx); err != nil {
					p.PutMsg(m)
					continue input
				}
			}
		}

		// run the callbacks
	callbacks:
		for _, cb := range mx.cbs {
			// skip the callback?
			if cb.Id != 0 && mx.Input.Id == cb.Id {
				continue // skip own messages
			} else if cb.Enabled != nil && !cb.Enabled.Load() {
				continue // disabled
			} else if cb.dropped.Load() {
				continue // permanently dropped
			}

			// need to parse first?
			if m.Upper == msg.INVALID && (!cb.Raw || len(cb.Filter) > 0) {
				if p.ParseMsg(m) != nil {
					p.PutMsg(m)
					continue input // parse error, drop the message
				}
			}

			// evaluate callback message filters?
			for _, f := range cb.Filter {
				if !eval.Run(f) {
					continue callbacks // try next callback
				}
			}

			// callback rate limiter?
			if cb.LimitRate != nil {
				if cb.LimitSkip {
					if !cb.LimitRate.Allow() {
						continue callbacks // try next callback
					}
				} else {
					if err := cb.LimitRate.Wait(p.Ctx); err != nil {
						p.PutMsg(m)
						continue input // pipe is stopping
					}
				}
			}

			// run the callback, block until done
			mx.Callback = cb
			if !cb.Func(m) {
				mx.Action.Drop()
			}
			mx.Callback = nil

			// what's next?
			if ctx.Err() != nil {
				p.PutMsg(m)
				return // pipe is stopping
			} else if mx.Action.HasDrop() {
				p.PutMsg(m)
				continue input // next message
			} else if mx.Action.HasAccept() {
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
			// new UNIX timestamp for UPDATE?
			if t > last_update { // local check to reduce atomic ops
				last_update = t
				oldt := l.LastUpdate.Load()
				if t > oldt && l.LastUpdate.CompareAndSwap(oldt, t) {
					p.Event(EVENT_UPDATE, m.Dir, t)
				}
			}

			// an End-of-RIB marker?
			if !eor_done && m.Len() < 32 && m.Parse(p.Caps) == nil {
				// initialize eor_todo?
				if eor_todo == 0 {
					if c, ok := p.Caps.Get(caps.CAP_MP).(*caps.MP); ok {
						eor_todo = len(c.Proto)
					} else {
						eor_todo = 1 // at least IPv4 unicast
					}
				}

				// already seen for all AFs? (AS_INVALID marks all AFs seen)
				if _, loaded := l.EoR.Load(afi.AS_INVALID); loaded || eor_todo == 0 {
					eor_done = true
					break
				}

				// get Address Family
				as := afi.AS_IPV4_UNICAST
				if m.Len() == msg.HEADLEN+msg.UPDATE_MINLEN {
					// FOUND: 23 bytes means this is the legacy IPv4 unicast EoR
				} else if a := m.Update.Attrs; a.Len() != 1 {
					break // EoR must have 1 attribute total
				} else if unreach, ok := a.Get(attrs.ATTR_MP_UNREACH).(*attrs.MP); !ok || len(unreach.Data) != 0 {
					break // EoR must have an empty ATTR_MP_UNREACH
				} else {
					as = unreach.AS // FOUND: this is the marker for given <AFI,SAFI>
				}

				// already seen this AF?
				if _, loaded := l.EoR.LoadOrStore(as, t); loaded {
					break
				} else { // it's a new AF, announce
					p.Event(EVENT_EOR_AF, m.Dir, as.Afi(), as.Safi())
				}

				// seen as many EoRs as in Caps?
				if l.EoR.Size() >= eor_todo {
					eor_done = true
					if _, loaded := l.EoR.LoadOrStore(afi.AS_INVALID, t); !loaded {
						p.Event(EVENT_EOR, m.Dir) // we were the first, announce
					}
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
	case <-in.Pipe.Ctx.Done():
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
	write_error = ErrInClosed
	defer func() {
		if write_error != nil {
			recover()
			in.Pipe.PutMsg(m)
		}
	}()
	in.In <- m
	return nil
}
