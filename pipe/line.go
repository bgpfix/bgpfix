package pipe

import (
	"bytes"
	"io"
	"sync/atomic"

	"github.com/bgpfix/bgpfix/msg"
)

// Line implements one direction of a Pipe: possibly several input processors
// run messages through callbacks and write the results to a common output.
type Line struct {
	Pipe *Pipe   // parent pipe
	Dir  msg.Dir // line direction

	// the default Input, which processes messages through all callbacks.
	Input

	// Out is the Line output, where you can read processed messages from.
	Out chan *msg.Msg

	// UNIX timestamp (seconds) of the last valid OPEN message
	LastOpen atomic.Int64

	// UNIX timestamp (seconds) of the last KEEPALIVE message
	LastAlive atomic.Int64

	// UNIX timestamp (seconds) of the last UPDATE message
	LastUpdate atomic.Int64

	// the OPEN message that updated LastOpen
	Open atomic.Pointer[msg.Open]

	inputs []*Input      // all input processors, [0] is the default .Input
	seq    atomic.Int64  // last seq number assigned
	obuf   bytes.Buffer  // output buffer
	done   chan struct{} // closed when done
}

// attach line inputs
func (l *Line) attach() {
	p := l.Pipe
	l.done = make(chan struct{})

	// the default input
	l.Input.attach(p, l)
	l.inputs = append(l.inputs, &l.Input)

	// inputs from Options
	for _, li := range p.Options.Inputs {
		if li != nil && li.Dir == l.Dir {
			li.attach(p, l)
			l.inputs = append(l.inputs, li)
		}
	}
}

// start starts all input processors
func (l *Line) start() {
	for _, in := range l.inputs {
		go in.process()
	}

	// close line output when all processors finish
	go func() {
		for _, in := range l.inputs {
			in.Wait()
		}
		l.CloseOutput()
		close(l.done)
	}()
}

// Wait blocks until all processing is done
func (l *Line) Wait() {
	<-l.done
}

// Close safely closes all inputs, which should eventually stop the line
func (l *Line) Close() {
	for _, in := range l.inputs {
		in.Close()
	}
}

// CloseOutput safely closes the output channel.
func (l *Line) CloseOutput() {
	defer func() { recover() }()
	close(l.Out)
}

// WriteOutput safely sends m to l.Out, avoiding a panic if closed.
func (l *Line) WriteOutput(m *msg.Msg) (write_error error) {
	defer func() {
		if recover() != nil {
			write_error = ErrOutClosed
			l.Pipe.PutMsg(m)
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
		err = m.Marshal(p.Caps)
		if err != nil {
			p.PutMsg(m)
			break
		}

		// write m.Data to buf
		_, err = m.WriteTo(buf)
		p.PutMsg(m)

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
		err = m.Marshal(p.Caps)
		if err != nil {
			p.PutMsg(m)
			break
		}

		// write m.Data to w
		k, err = m.WriteTo(w)
		p.PutMsg(m)
		n += k

		// continue?
		if err != nil {
			break
		}
	}

	return n, err
}
