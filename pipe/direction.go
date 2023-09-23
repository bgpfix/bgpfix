package pipe

import (
	"bytes"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bgpfix/bgpfix/msg"
)

// Direction represents a particular direction of messages in a Pipe
type Direction struct {
	// parent Pipe
	Pipe *Pipe

	// opposite pipe direction from the parent pipe
	Opposite *Direction

	// destination of messages flowing in this Direction
	Dst msg.Dst

	// In is the pipe input, where you write messages to be processed.
	//
	// You can get empty messages using Pipe.Get(). If your message
	// has a Pipe.Context with a Callback set, processing will start
	// just after that Callback (if found in the pipe).
	In chan *msg.Msg

	// Out is the pipe output, where you read processed messages.
	//
	// You should dispose used messages using Pipe.Put().
	Out chan *msg.Msg

	// the last OPEN message that made it to Out
	Open atomic.Pointer[msg.Open]

	// UNIX timestamp of the last KEEPALIVE message
	Alive atomic.Int64

	// input/output buffers
	ibuf []byte
	obuf bytes.Buffer

	// number of messages read from In
	seq atomic.Int64

	// dir statistics
	stats Stats

	// callbacks
	open         []*Callback
	update       []*Callback
	keepalive    []*Callback
	notification []*Callback
	refresh      []*Callback
	invalid      []*Callback
}

// BGP dir statistics
type Stats struct {
	Parsed  uint64
	Short   uint64
	Garbled uint64
}

// CloseInput safely closes the Input channel.
// The Output channel will eventually be closed too, after all queued messages have been processed.
func (d *Direction) CloseInput() {
	defer func() { recover() }()
	close(d.In)
}

// CloseOutput safely closes the Output channel.
// Input handlers will keep running until Input is closed.
func (d *Direction) CloseOutput() {
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
func (d *Direction) Write(src []byte) (n int, err error) {
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

// WriteMsg safely sends m to d.In, setting m.Seq if needed.
// It returns an error iff d.In was closed (instead of a panic).
func (d *Direction) WriteMsg(m *msg.Msg) (err error) {
	defer func() {
		if recover() != nil {
			err = ErrInClosed
		}
	}()
	if m.Seq == 0 {
		m.Seq = d.seq.Add(1)
	}
	d.In <- m
	return
}

// Handling callbacks ------------------------------

// Handler reads Input, runs all callbacks on incoming messages,
// and forwards the result to Output.
//
// The Output *can* be closed anytime, which will cause the resultant
// messages to be dropped on the floor (and re-used).
//
// Exits when dir.Input closes and is emptied. wg may be nil.
func (d *Direction) Handler(wg *sync.WaitGroup) {
	output_closed := d.handler(d.Out)
	if output_closed {
		d.handler(nil)
	}
	if wg != nil {
		wg.Done()
	}
}

func (d *Direction) handler(output chan *msg.Msg) (output_closed bool) {
	var (
		p     = d.Pipe
		input = d.In
		m     *msg.Msg
		cbs   []*Callback
	)

	// which events to generate in case of OPEN / KEEPALIVE?
	event_open, event_alive := EVENT_OPEN_R, EVENT_ALIVE_R
	if d.Dst == msg.DST_L {
		event_open, event_alive = EVENT_OPEN_L, EVENT_ALIVE_L
	}

	// catch panic due to write to closed channel
	catch := false
	defer func() {
		if catch && recover() != nil {
			p.Put(m)
			output_closed = true
		}
	}()

input:
	for m = range input {
		// metadata
		m.Dst = d.Dst
		if m.Seq == 0 {
			m.Seq = d.seq.Add(1)
		}
		if m.Time.IsZero() {
			m.Time = time.Now().UTC()
		}

		// select callbacks
		switch m.Type {
		case msg.UPDATE:
			cbs = d.update
		case msg.KEEPALIVE:
			cbs = d.keepalive
		case msg.NOTIFY:
			cbs = d.notification
		case msg.REFRESH:
			cbs = d.refresh
		case msg.OPEN:
			cbs = d.open
		default:
			cbs = d.invalid
		}

		// setup pipe context
		pc := PipeContext(m)
		pc.Pipe = p
		pc.Dir = d
		pc.Action.Clear()

		// skip past a callback?
		if pc.Callback != nil {
			from := 0
			for i, cb := range cbs {
				if cb == pc.Callback {
					from = i + 1
				} else if from > 0 {
					break
				}
			}
			cbs = cbs[from:]
		}

		// run callbacks
		for _, cb := range cbs {
			// skip?
			if cb.Enabled != nil && !cb.Enabled.Load() {
				continue
			}

			// set the current callback
			pc.Callback = cb

			// need to parse first?
			if !cb.Raw && m.Upper == msg.INVALID {
				if err := m.ParseUpper(p.Caps); err != nil {
					p.Event(EVENT_PARSE_ERROR, m, err)
					continue input // next message
				}
			}

			// run and wait
			pc.Action |= cb.Func(m)

			// what's next?
			if pc.Action.Is(ACTION_DROP) {
				p.Put(m)
				continue input // next message
			} else if pc.Action.Is(ACTION_ACCEPT) {
				break // take it as-is
			}
		}

		// special-purpose message?
		switch m.Type {
		case msg.OPEN: // take it if valid
			if m.ParseUpper(p.Caps) == nil {
				pc.Action |= ACTION_BORROW // don't re-use in pool
				d.Open.Swap(&m.Open)
				p.Event(event_open, m)
			}

		case msg.KEEPALIVE: // take it if bigger timestamp
			newt := m.Time.Unix()
			oldt := d.Alive.Load()
			if newt > oldt && d.Alive.CompareAndSwap(oldt, newt) {
				p.Event(event_alive, m)
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

	return false // all ok
}

// Output readers ------------------------------

// Read reads d.Out and writes raw BGP data to dst
// Must not be used concurrently.
// TODO: stats
func (d *Direction) Read(dst []byte) (int, error) {
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
func (d *Direction) WriteTo(w io.Writer) (int64, error) {
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

// Stats returns dir statistics FIXME
func (d *Direction) Stats() *Stats {
	return &d.stats
}

func (d *Direction) addCallback(cb *Callback) {
	if cb == nil || cb.Func == nil {
		return
	}

	if len(cb.Types) == 0 {
		d.open = append(d.open, cb)
		d.keepalive = append(d.keepalive, cb)
		d.update = append(d.update, cb)
		d.notification = append(d.notification, cb)
		d.refresh = append(d.refresh, cb)
		d.invalid = append(d.invalid, cb)
		return
	}

	for _, t := range cb.Types {
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
