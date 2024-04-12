package mrt

import (
	"fmt"
	"io"

	"github.com/bgpfix/bgpfix/msg"
	"github.com/bgpfix/bgpfix/pipe"
)

// Reader reads MRT-BGP4MP messages into a pipe.Input.
type Reader struct {
	pipe *pipe.Pipe  // target pipe
	in   *pipe.Input // target input

	ibuf []byte // input buffer
	mrt  *Mrt   // raw MRT message

	NoTags bool        // ignore message tags?
	Stats  ReaderStats // our stats
}

// BGP reader statistics
type ReaderStats struct {
	Parsed     uint64 // parsed messages (total)
	ParsedBgp  uint64 // parsed BGP4MP messages
	ParsedSkip uint64 // skipped non-BGP4MP messages
	Short      uint64 // data in buffer too short, should retry
	Garbled    uint64 // parse error
}

// NewReader returns a new Reader.
func NewReader(p *pipe.Pipe, input *pipe.Input) *Reader {
	return &Reader{
		pipe: p,
		in:   input,
		mrt:  NewMrt(),
	}
}

// Write implements io.Writer and reads all MRT-BGP4MP messages from src
// into br.in. Must not be used concurrently.
func (br *Reader) Write(src []byte) (n int, err error) {
	return br.WriteFunc(src, nil)
}

// WriteFunc is the same as Write(), but takes an optional callback function
// to be called just before the message is accepted for processing. If the callback
// returns false, the message is silently dropped instead.
func (br *Reader) WriteFunc(src []byte, cb pipe.CallbackFunc) (n int, err error) {
	var (
		p     = br.pipe
		stats = &br.Stats
	)

	// append src and switch to inbuf if needed
	n = len(src) // NB: always return n=len(src)
	raw := src
	if len(br.ibuf) > 0 {
		br.ibuf = append(br.ibuf, src...)
		raw = br.ibuf // [1]
	}

	// on return, leave remainder at start of br.inbuf?
	defer func() {
		if len(raw) == 0 {
			br.ibuf = br.ibuf[:0]
		} else if len(br.ibuf) == 0 || &raw[0] != &br.ibuf[0] { // NB: trick to avoid self-copy [1]
			br.ibuf = append(br.ibuf[:0], raw...)
		} // otherwise there is something left, but already @ s.inbuf[0:]
	}()

	// process until raw is empty
	for len(raw) > 0 {
		// parse as raw MRT message
		mrt := br.mrt.Reset()
		off, perr := mrt.FromBytes(raw)
		switch perr {
		case nil:
			stats.Parsed++
			raw = raw[off:]
		case io.ErrUnexpectedEOF: // need more data
			stats.Short++
			return n, nil // defer will buffer raw
		default: // parse error, try to skip the garbled data
			stats.Garbled++
			if off > 0 {
				raw = raw[off:] // buffer the remainder for re-try
			} else {
				raw = nil // no idea, throw out
			}
			return n, fmt.Errorf("MRT: %w", perr)
		}

		// parse as BGP4MP
		switch err := mrt.Parse(); err {
		case nil:
			stats.ParsedBgp++ // success
		case ErrType, ErrSub:
			stats.ParsedSkip++
			continue
		default:
			stats.Garbled++
			return n, fmt.Errorf("BGP4MP: %w", err)
		}

		// write to BGP msg
		m := p.GetMsg()
		if err := mrt.Bgp4.ToMsg(m, !br.NoTags); err != nil {
			p.PutMsg(m)
			return n, err
		}

		// prepare m
		if cb != nil && !cb(m) {
			p.PutMsg(m)
			continue // silent skip
		}

		// sail!
		m.CopyData()
		if err := br.in.WriteMsg(m); err != nil {
			return n, fmt.Errorf("pipe: %w", err)
		}
		mrt.Reset()
	}

	// exactly n bytes consumed and processed, no error
	return n, nil
}

// FromBytes parses the first MRT-BGP4MP message in buf, and references it in m.
// Does not buffer or copy buf. Can be used concurrently. mrt may be nil
func (br *Reader) FromBytes(buf []byte, m *msg.Msg, mrt *Mrt) (n int, err error) {
	// intermediate buffer
	if mrt == nil {
		mrt = NewMrt()
	} else {
		mrt.Reset()
	}

	// parse as raw MRT message
	n, err = mrt.FromBytes(buf)
	if err != nil {
		return n, fmt.Errorf("MRT: %w", err)
	}

	// parse as MRT-BGP4MP
	b4 := &mrt.Bgp4
	switch err := b4.Parse(); err {
	case nil:
		break // success
	case ErrSub:
		return n, ErrSub
	default:
		return n, fmt.Errorf("BGP4MP: %w", err)
	}

	return n, b4.ToMsg(m, !br.NoTags)
}
