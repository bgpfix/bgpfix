package pipe

import (
	"bytes"
	"io"
	"sync/atomic"

	"github.com/bgpfix/bgpfix/msg"
)

// Output represents an output of a Pipe
type Output struct {
	Pipe *Pipe  // parent pipe
	Id   int    // optional output id number
	Name string // optional name

	// Out is the output, where to write outgoing messages to.
	// nil means drop the messages on the floor.
	Out chan *msg.Msg

	// UNIX timestamp (seconds) of the last valid OPEN message
	LastOpen atomic.Int64

	// UNIX timestamp (seconds) of the last KEEPALIVE message
	LastAlive atomic.Int64

	// UNIX timestamp (seconds) of the last UPDATE message
	LastUpdate atomic.Int64

	// the OPEN message that updated LastOpen
	Open atomic.Pointer[msg.Open]

	obuf bytes.Buffer // output buffer
}

func NewOutput(p *Pipe, buflen int) *Output {
	return &Output{
		Pipe: p,
		Out:  make(chan *msg.Msg, 10),
	}
}

// Close safely closes the .Out channel.
func (po *Output) Close() {
	defer func() { recover() }()
	close(po.Out)
}

// WriteMsg queues m for output, doing some housekeeping
func (po *Output) WriteMsg(m *msg.Msg) (write_error error) {
	p := po.Pipe

	// m updates the UNIX timestamp for its type?
	t := m.Time.Unix()
	switch m.Type {
	case msg.OPEN:
		oldt := po.LastOpen.Load()
		if t > oldt && po.LastOpen.CompareAndSwap(oldt, t) {
			if m.ParseUpper(p.Caps) == nil {
				Context(m).Action.Add(ACTION_BORROW)
				po.Open.Store(&m.Open)
				p.Event(EVENT_OPEN, m.Dst, t, oldt)
			}
		}

	case msg.KEEPALIVE:
		oldt := po.LastAlive.Load()
		if t > oldt && po.LastAlive.CompareAndSwap(oldt, t) {
			p.Event(EVENT_ALIVE, m.Dst, t, oldt)
		}

	case msg.UPDATE:
		oldt := po.LastUpdate.Load()
		if t > oldt && po.LastUpdate.CompareAndSwap(oldt, t) {
			p.Event(EVENT_UPDATE, m.Dst, t, oldt)
		}
	}

	// drop on the floor?
	if po.Out == nil {
		p.Put(m)
	}

	// in case of closed channel
	defer func() {
		if recover() != nil {
			write_error = ErrOutClosed
			p.Put(m)
		}
	}()

	// forward to output
	po.Out <- m
	return nil
}

// Read reads po.Out and writes raw BGP data to dst
// Must not be used concurrently.
func (po *Output) Read(dst []byte) (int, error) {
	var (
		p      = po.Pipe
		buf    = &po.obuf
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
	for m := range po.Out {
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
		} else if len(po.Out) == 0 {
			break // avoid blocking for more data
		}
	}

	// rewrite into p, propagate err
	n, _ := buf.Read(dst)
	return n, err
}

// WriteTo implements io.WriterTo interface, writing raw BGP data to w
func (po *Output) WriteTo(w io.Writer) (int64, error) {
	var (
		p    = po.Pipe
		err  = io.EOF // default error
		n, k int64
	)

	for m := range po.Out {
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
