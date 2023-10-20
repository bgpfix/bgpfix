package pipe

import (
	"io"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bgpfix/bgpfix/msg"
)

// Input processes incoming BGP messages through Pipe Callbacks.
type Input struct {
	Id   int     // optional input id number (zero means none)
	Name string  // optional name
	Dst  msg.Dst // destination of messages flowing in this input

	// In is the input, where to read incoming messages from.
	// Starting with nil means create a new channel.
	In chan *msg.Msg

	// statistics
	Stats struct {
		Parsed  uint64
		Short   uint64
		Garbled uint64
	}

	p       *Pipe           // parent pipe
	ibuf    []byte          // input buffer
	seq     *atomic.Int64   // sequence numbers source
	cbs     [16][]*Callback // callbacks
	reverse bool            // run callbacks in reverse?
}

func (pi *Input) apply(p *Pipe) {
	pi.p = p
	opts := &p.Options

	// destination?
	if pi.Dst == 0 {
		pi.Dst = msg.DST_R
	}

	// seq numbers
	if pi.Dst == msg.DST_L {
		pi.seq = &p.lseq
	} else {
		pi.seq = &p.rseq
	}

	// input
	if pi.In == nil {
		pi.In = make(chan *msg.Msg, 10)
	}

	// reverse?
	if pi.Dst == msg.DST_L {
		pi.reverse = opts.ReverseL
	} else {
		pi.reverse = opts.ReverseR
	}

	// callbacks
	var cbs []*Callback
	cbs = append(cbs, p.cbs...)
	if pi.reverse {
		slices.Reverse(cbs)
	}

	// reference only the relevant callbacks in l.cbs
	for _, cb := range cbs {
		// check dst
		if cb.Dst != 0 && cb.Dst != pi.Dst {
			continue
		}

		// message types?
		var types []msg.Type
		if len(cb.Types) == 0 {
			for i := 1; i < len(pi.cbs); i++ {
				types = append(types, msg.Type(i))
			}
		} else {
			types = append(types, cb.Types...)
			slices.Sort(types)
			types = slices.Compact(types)
		}

		// reference relevant callbacks
		for _, t := range types {
			if t < msg.Type(len(pi.cbs)) {
				pi.cbs[t] = append(pi.cbs[t], cb)
			} else {
				pi.cbs[0] = append(pi.cbs[0], cb)
			}
		}
	}
}

// run runs the Input. wg may be nil.
func (pi *Input) run(wg *sync.WaitGroup) error {
	// target
	out := pi.p.Rout
	if pi.Dst == msg.DST_L {
		out = pi.p.Lout
	}

	// process as long there's input to do
	err := pi.process(out)
	if err == ErrOutClosed {
		err = pi.process(nil) // retry without writing to output
	}

	// done!
	if wg != nil {
		wg.Done()
	}

	return err
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
	pc.Pipe = pi.p

	// message metadata
	m.Dst = pi.Dst
	if m.Seq == 0 {
		m.Seq = pi.seq.Add(1)
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

func (pi *Input) process(output chan *msg.Msg) (err error) {
	var (
		p     = pi.p
		input = pi.In
		m     *msg.Msg
	)

	// catch panic due to write to closed channel
	catch := false
	defer func() {
		if catch && recover() != nil {
			p.Put(m)
			err = ErrOutClosed
		}
	}()

input:
	for m = range input {
		// get context, clear actions except for BORROW
		pc := pi.prepare(m)
		pc.Action.Clear()

		// run the callbacks
		for len(pc.cbs) > 0 {
			// eat first callback
			cb := pc.cbs[0]
			pc.cbs = pc.cbs[1:]

			// skip the callback?
			if pi.reverse {
				// TODO: embed skip_*
				if pi.skip_backward(pc.SkipId, cb.Id) {
					continue
				}
			} else {
				if pi.skip_forward(pc.SkipId, cb.Id) {
					continue
				}
			}

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

		// forward to output if possible
		if output != nil {
			catch = true
			output <- m
			catch = false
		} else {
			p.Put(m)
		}
	}

	return nil // all ok, work done
}

func (pi *Input) skip_forward(pcid, cbid int) bool {
	switch {
	case pcid == 0 || cbid == 0:
		return false
	case pcid < 0:
		return cbid <= -pcid
	default:
		return cbid < pcid
	}
}

func (pi *Input) skip_backward(pcid, cbid int) bool {
	switch {
	case pcid == 0 || cbid == 0:
		return false
	case pcid < 0:
		return cbid >= -pcid
	default:
		return cbid > pcid
	}
}

// Close safely closes the .In channel, which should eventually stop the Input
func (pi *Input) Close() {
	defer func() { recover() }()
	close(pi.In)
}

// WriteMsg safely sends m to l.In, returning an error instead of a panic if l.In is closed.
// It assigns a sequence number and timestamp before writing to the channel.
func (pi *Input) WriteMsg(m *msg.Msg) (err error) {
	pi.prepare(m)
	defer func() {
		if recover() != nil {
			err = ErrInClosed
		}
	}()
	pi.In <- m
	return
}

// Write implements io.Writer and reads all BGP messages from src into l.In.
// Copies bytes from src. Consumes what it can, buffers the remainder if needed.
// Returns n equal to len(src). May block if l.In is full.
//
// In case of a non-nil err, call Write(nil) to re-try using the buffered remainder,
// until it returns a nil err.
//
// Must not be used concurrently.
func (pi *Input) Write(src []byte) (n int, err error) {
	var (
		p   = pi.p
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
			return n, perr
		}
	}

	// exactly len(src) bytes consumed and processed, no error
	return n, nil
}
