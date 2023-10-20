package pipe

import (
	"bytes"
	"io"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bgpfix/bgpfix/msg"
)

// Output represents an output of a Pipe for particular direction
type Output struct {
	Dst msg.Dst // destination of messages

	p   *Pipe         // parent pipe
	Out chan *msg.Msg // output channel

	// UNIX timestamp (seconds) of the last valid OPEN message
	LastOpen atomic.Int64

	// UNIX timestamp (seconds) of the last KEEPALIVE message
	LastAlive atomic.Int64

	// UNIX timestamp (seconds) of the last UPDATE message
	LastUpdate atomic.Int64

	// the last valid OPEN message that updated TimeOpen
	Open atomic.Pointer[msg.Open]

	// input/output buffers
	ibuf []byte
	obuf bytes.Buffer
}

// CloseInput safely closes the Input channel.
// The Output channel will eventually be closed too, after all queued messages have been processed.
func (d *Output) CloseInput() {
	defer func() { recover() }()
	close(d.In)
}

// CloseOutput safely closes the Output channel.
// Input handlers will keep running until Input is closed.
func (d *Output) CloseOutput() {
	defer func() { recover() }()
	close(d.Out)
}

// Input writers ------------------------------

// Write implements io.Writer and reads all BGP messages from src into dir.In.
// Copies bytes from src. Consumes what it can, buffers the remainder if needed.
// Returns n equal to len(src). May block if dir.In is full.
//
// In case of a non-nil err, call Write(nil) to re-try using the buffered remainder,
// untill it returns a nil err.
//
// Must not be used concurrently.
func (d *Output) Write(src []byte) (n int, err error) {
	var (
		p   = d.Pipe
		ss  = &d.stats
		now = time.Now().UTC()
	)

	// append src and switch to inbuf if needed
	n = len(src) // NB: always return n=len(src)
	raw := src
	if len(d.ibuf) > 0 {
		d.ibuf = append(d.ibuf, raw...)
		raw = d.ibuf // [1]
	}

	// on return, leave the remainder at the start of d.inbuf?
	defer func() {
		if len(raw) == 0 {
			d.ibuf = d.ibuf[:0]
		} else if len(d.ibuf) == 0 || &raw[0] != &d.ibuf[0] { // NB: trick to avoid self-copy [1]
			d.ibuf = append(d.ibuf[:0], raw...)
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
		if err := d.WriteMsg(m); err != nil {
			return n, perr
		}
	}

	// exactly len(src) bytes consumed and processed, no error
	return n, nil
}

// WriteMsg safely sends m to d.In, returning an error instead of a panic
// if d.In is closed.
func (d *Output) WriteMsg(m *msg.Msg) (err error) {
	d.prepare(m)
	defer func() {
		if recover() != nil {
			err = ErrInClosed
		}
	}()
	d.In <- m
	return
}

// prepare prepares metadata and context of m for processing in this Direction.
// The message type must already be set.
func (d *Output) prepare(m *msg.Msg) (pc *PipeContext) {
	pc = Context(m)
	if pc.prepared {
		return
	} else {
		pc.prepared = true
	}

	// message metadata
	m.Dst = d.Dst
	if m.Seq == 0 {
		m.Seq = d.seq.Add(1)
	}
	if m.Time.IsZero() {
		m.Time = time.Now().UTC()
	}

	// pipe context
	pc.Pipe = d.Pipe
	pc.Dir = d
	if pc.cbs == nil {
		switch m.Type {
		case msg.UPDATE:
			pc.cbs = d.update
		case msg.KEEPALIVE:
			pc.cbs = d.keepalive
		case msg.NOTIFY:
			pc.cbs = d.notification
		case msg.REFRESH:
			pc.cbs = d.refresh
		case msg.OPEN:
			pc.cbs = d.open
		default:
			pc.cbs = d.invalid
		}
	}

	return
}

// Handling callbacks ------------------------------

// Process reads input, runs all callbacks on incoming messages,
// and forwards the result to d.Out.
//
// The d.Out channel *can* be closed anytime, which will cause the resultant
// messages to be dropped on the floor (and possibly re-used).
//
// Exits when input closes and is emptied. wg may be nil.
func (d *Output) Process(input chan *msg.Msg, wg *sync.WaitGroup) {
	if wg != nil {
		defer wg.Done()
	}

	out := d.Out
	for m := range input {
		output_closed := d.process(m, out)
		if output_closed {
			out = nil
		}
	}
}

// ProcessMsg runs all callbacks on message m and forwards the result to d.Out.
func (d *Output) ProcessMsg(m *msg.Msg) {
	d.prepare(m)
	d.process(m, d.Out)
}

func (d *Output) process(m *msg.Msg, output chan *msg.Msg) (output_closed bool) {
	var (
		p = d.Pipe
	)

	// get context, clear actions except for BORROW
	pc := d.prepare(m)
	pc.Action.Clear()

	// run the callbacks
	for len(pc.cbs) > 0 {
		// eat first callback
		cb := pc.cbs[0]
		pc.cbs = pc.cbs[1:]

		// skip the callback?
		if d.reverse {
			if d.skip_backward(pc.SkipId, cb.Id) {
				continue
			}
		} else {
			if d.skip_forward(pc.SkipId, cb.Id) {
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
				p.Event(EVENT_PARSE, d.Dst, m, err)
				return
			}
		}

		// run and wait
		pc.Callback = cb
		pc.Action |= cb.Func(m)
		pc.Callback = nil

		// what's next?
		if pc.Action.Is(ACTION_DROP) {
			p.Put(m)
			return
		} else if pc.Action.Is(ACTION_ACCEPT) {
			break // take it as-is
		}
	}

	// new timestamp?
	switch m.Type {
	case msg.OPEN:
		newt := m.Time.Unix()
		oldt := d.LastOpen.Load()
		if newt > oldt && d.LastOpen.CompareAndSwap(oldt, newt) {
			if m.ParseUpper(p.Caps) == nil {
				Context(m).Action.Add(ACTION_BORROW)
				d.Open.Store(&m.Open)
				p.Event(EVENT_OPEN, d.Dst, newt, oldt)
			}
		}
	case msg.KEEPALIVE:
		newt := m.Time.Unix()
		oldt := d.LastAlive.Load()
		if newt > oldt && d.LastAlive.CompareAndSwap(oldt, newt) {
			p.Event(EVENT_ALIVE, d.Dst, newt, oldt)
		}
	case msg.UPDATE:
		newt := m.Time.Unix()
		oldt := d.LastUpdate.Load()
		if newt > oldt && d.LastUpdate.CompareAndSwap(oldt, newt) {
			p.Event(EVENT_UPDATE, d.Dst, newt, oldt)
		}
	}

	// forward to output if possible
	if output != nil {
		// in case of closed output
		defer func() {
			if recover() != nil {
				output_closed = true
				p.Put(m)
			}
		}()
		output <- m
	} else {
		p.Put(m)
	}

	return
}

// Output readers ------------------------------

// Read reads d.Out and writes raw BGP data to dst
// Must not be used concurrently.
// TODO: stats
func (d *Output) Read(dst []byte) (int, error) {
	var (
		p      = d.Pipe
		buf    = &d.obuf
		enough = len(dst) - 10*1024 // ditch the last 10KiB
		err    = io.EOF             // default error
	)

	// anything buffered already?
	if buf.Len() > 0 {
		return buf.Read(dst) // [2]
	} else {
		buf.Reset() // NB: needed to re-use buf space after [2]
	}

	// marshal from dir's output into obuf as much as possible
	for m := range d.Out {
		// marshal upper layer to m.Data if needed
		err = m.MarshalUpper(p.Caps)
		if err != nil {
			p.Put(m)
			break
		}

		// write m.Data to buf
		_, err = m.WriteTo(buf)
		p.Put(m)

		// what's next?
		if err != nil {
			break
		} else if buf.Len() >= enough {
			break // already enough data buffered
		} else if len(d.Out) == 0 {
			break // avoid blocking for more data
		}
	}

	// rewrite into p, propagate err
	n, _ := buf.Read(dst)
	return n, err
}

// WriteTo implements io.WriterTo interface, writing raw BGP data to w
func (d *Output) WriteTo(w io.Writer) (int64, error) {
	var (
		n, k int64
		err  = io.EOF // default error
		p    = d.Pipe
	)

	for m := range d.Out {
		// marshal upper layer to m.Data if needed
		err = m.MarshalUpper(p.Caps)
		if err != nil {
			p.Put(m)
			break
		}

		// write m.Data to w
		k, err = m.WriteTo(w)
		p.Put(m)
		n += k

		// continue?
		if err != nil {
			break
		}
	}

	return n, err
}

// --------------------------

// Stats returns dir statistics FIXME: concurrent access
func (d *Output) Stats() *Stats {
	return &d.stats
}

func (d *Output) addCallbacks(src []*Callback) {
	// collect my valid callbacks
	var cbs []*Callback
	for _, cb := range src {
		if cb == nil || cb.Func == nil {
			continue
		}
		if cb.Dst == 0 || cb.Dst == d.Dst {
			cbs = append(cbs, cb)
		}
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
		if d.reverse {
			return b.Order - a.Order
		} else {
			return a.Order - b.Order
		}
	})

	// add to this direction
	for _, cb := range cbs {
		d.addCallback(cb)
	}
}

func (d *Output) addCallback(cb *Callback) {
	if len(cb.Types) == 0 {
		d.open = append(d.open, cb)
		d.keepalive = append(d.keepalive, cb)
		d.update = append(d.update, cb)
		d.notification = append(d.notification, cb)
		d.refresh = append(d.refresh, cb)
		d.invalid = append(d.invalid, cb)
		return
	}

	slices.Sort(cb.Types)
	for _, t := range slices.Compact(cb.Types) {
		switch t {
		case msg.OPEN:
			d.open = append(d.open, cb)
		case msg.KEEPALIVE:
			d.keepalive = append(d.keepalive, cb)
		case msg.UPDATE:
			d.update = append(d.update, cb)
		case msg.NOTIFY:
			d.notification = append(d.notification, cb)
		case msg.REFRESH:
			d.refresh = append(d.refresh, cb)
		default:
			d.invalid = append(d.invalid, cb)
		}
	}
}

func (d *Output) skip_forward(pcid, cbid int) bool {
	switch {
	case pcid == 0 || cbid == 0:
		return false
	case pcid < 0:
		return cbid <= -pcid
	default:
		return cbid < pcid
	}
}

func (d *Output) skip_backward(pcid, cbid int) bool {
	switch {
	case pcid == 0 || cbid == 0:
		return false
	case pcid < 0:
		return cbid >= -pcid
	default:
		return cbid > pcid
	}
}
