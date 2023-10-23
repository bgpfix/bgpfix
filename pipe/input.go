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
	Pipe *Pipe  // parent pipe
	Id   int    // optional input id number
	Name string // optional name

	// direction to impose on incoming messages
	Dst msg.Dst

	// In is the input, where to read incoming messages from.
	// nil means create a new channel.
	In chan *msg.Msg

	// Out is the output, where to write processed messages to.
	// nil means use the default Pipe output for Dst.
	Out *Output

	// statistics
	Stats struct {
		Parsed  uint64
		Short   uint64
		Garbled uint64
	}

	ibuf    []byte          // input buffer
	seq     *atomic.Int64   // sequence numbers source
	cbs     [16][]*Callback // callbacks
	reverse bool            // run callbacks in reverse?
}

func (pi *Input) apply(p *Pipe) {
	var (
		opts = &p.Options
	)

	pi.Pipe = p

	// destination?
	switch pi.Dst {
	case msg.DST_L:
		pi.Out = p.L
		pi.seq = &p.lseq
		pi.reverse = opts.ReverseL
	default:
		pi.Dst = msg.DST_R // override
		pi.Out = p.R
		pi.seq = &p.rseq
		pi.reverse = opts.ReverseR
	}

	// callbacks
	var cbs []*Callback
	cbs = append(cbs, p.cbs...)
	if pi.reverse {
		slices.Reverse(cbs)
	}

	// reference only the relevant callbacks in pi.cbs
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

// prepare prepares metadata and context of m for processing in this Line.
// The message type must already be set.
func (pi *Input) prepare(m *msg.Msg) (pc *PipeContext) {
	// already prepared?
	pc = Context(m)
	if pc.Input == pi {
		return
	}
	pc.Input = pi
	pc.Pipe = pi.Pipe

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

	// TODO: assign SkipId

	return
}

func (pi *Input) process(wg *sync.WaitGroup) {
	var (
		p       = pi.Pipe
		input   = pi.In
		output  = pi.Out
		reverse = pi.reverse
		m       *msg.Msg
	)

	if wg != nil {
		defer wg.Done()
	}

input:
	for m = range input {
		// get context, clear actions except for BORROW
		pc := pi.prepare(m)
		pc.Action.Clear()
		pcid := pc.SkipId

		// run the callbacks
		for len(pc.cbs) > 0 {
			// eat first callback
			cb := pc.cbs[0]
			pc.cbs = pc.cbs[1:]

			// skip the callback?
			if cbid := cb.Id; pcid != 0 && cbid != 0 {
				if reverse {
					if pcid < 0 && cbid >= -pcid {
						continue
					} else if cbid > pcid {
						continue
					}
				} else {
					if pcid < 0 && cbid <= -pcid {
						continue
					} else if cbid < pcid {
						continue
					}
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

		// forward to output
		output.WriteMsg(m)
	}
}

// Close safely closes the .In channel, which should eventually stop the Input
func (pi *Input) Close() {
	defer func() { recover() }()
	close(pi.In)
}

// WriteMsg safely sends m to pi.In, avoiding a panic if pi.In is closed.
// It assigns a sequence number and timestamp before writing to the channel.
func (pi *Input) WriteMsg(m *msg.Msg) (write_error error) {
	pi.prepare(m)
	defer func() {
		if recover() != nil {
			write_error = ErrInClosed
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
