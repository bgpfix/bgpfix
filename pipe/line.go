package pipe

import (
	"bytes"
	"io"
	"sync"
	"sync/atomic"

	"github.com/bgpfix/bgpfix/msg"
)

// Line represents one direction of a Pipe: inputs with a common output
type Line struct {
	Pipe *Pipe   // parent pipe
	Dst  msg.Dst // line direction

	// Out is the output, where to write outgoing messages to.
	Out chan *msg.Msg

	// UNIX timestamp (seconds) of the last valid OPEN message
	LastOpen atomic.Int64

	// UNIX timestamp (seconds) of the last KEEPALIVE message
	LastAlive atomic.Int64

	// UNIX timestamp (seconds) of the last UPDATE message
	LastUpdate atomic.Int64

	// the OPEN message that updated LastOpen
	Open atomic.Pointer[msg.Open]

	inputs []*Input       // line inputs
	wg     sync.WaitGroup // running inputs
	seq    atomic.Int64   // last seq number assigned
	obuf   bytes.Buffer   // output buffer
}

// attach line inputs
func (l *Line) attach() {
	p := l.Pipe
	for _, li := range p.Options.Inputs {
		if li != nil && li.Dst == l.Dst {
			li.attach(p, l)
			l.inputs = append(l.inputs, li)
		}
	}
}

// StartInputs starts a processor goroutine for each input.
// Called automatically from Pipe.Start().
func (l *Line) StartInputs() {
	for _, li := range l.inputs {
		l.wg.Add(1)
		go li.process(&l.wg)
	}
}

// CloseInputs safely closes all inputs, which should eventually close the output.
func (l *Line) CloseInputs() {
	for _, li := range l.inputs {
		li.Close()
	}
}

// WaitInputs blocks until all inputs are done with processing.
func (l *Line) WaitInputs() {
	l.wg.Wait()
}

// CloseOutput safely closes the output channel.
func (l *Line) CloseOutput() {
	defer func() { recover() }()
	close(l.Out)
}

// WriteOut safely sends m to l.Out, avoiding a panic if closed.
func (l *Line) WriteOut(m *msg.Msg) (write_error error) {
	defer func() {
		if recover() != nil {
			write_error = ErrOutClosed
			l.Pipe.Put(m)
		}
	}()
	l.Out <- m
	return nil
}

// Read reads l.Out and writes raw BGP data to dst.
// Must not be used concurrently.
func (l *Line) Read(dst []byte) (int, error) {
	var (
		p      = l.Pipe
		buf    = &l.obuf
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
	for m := range l.Out {
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
		} else if len(l.Out) == 0 {
			break // avoid blocking for more data
		}
	}

	// rewrite into p, propagate err
	n, _ := buf.Read(dst)
	return n, err
}

// WriteTo implements io.WriterTo interface, writing raw BGP data to w
func (l *Line) WriteTo(w io.Writer) (int64, error) {
	var (
		p    = l.Pipe
		err  = io.EOF // default error
		n, k int64
	)

	for m := range l.Out {
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
