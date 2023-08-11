package mrt

import (
	"io"

	"github.com/bgpfix/bgpfix/pipe"
)

// BgpSession wraps BGP session.Session and provides
// Write() that reads MRT-BGP4MP messages.
type BgpSession struct {
	Bgp   *pipe.Pipe      // BGP session
	Stats BgpSessionStats // MRT session stats

	inbuf  []byte
	mrtmsg Msg
	bgp4mp BgpMsg
}

// MRT BGP session statistics
type BgpSessionStats struct {
	Parsed     uint64 // parsed messages (total)
	ParsedBgp  uint64 // parsed BGP4MP messages
	ParsedSkip uint64 // skipped non-BGP4MP messages
	Short      uint64 // data in buffer too short, should retry
	Garbled    uint64 // parse error
}

// NewBgpSession returns a new MRT BgpSession
func NewBgpSession(bgp *pipe.Pipe) (*BgpSession, error) {
	s := &BgpSession{
		Bgp: bgp,
	}
	return s, nil
}

// Write implements io.Writer and reads all MRT-BGP4MP messages from p
// into BGP session Rx channel. See session.Session.Write for more context.
func (s *BgpSession) Write(p []byte) (n int, err error) {
	// prepare
	lenp := len(p)
	var raw []byte

	// append p and switch to inbuf if needed
	if len(s.inbuf) > 0 {
		s.inbuf = append(s.inbuf, p...)
		raw = s.inbuf // @1
	} else {
		raw = p
	}

	// on return, leave remainder at start of s.inbuf?
	defer func() {
		if len(raw) == 0 {
			s.inbuf = s.inbuf[:0]
		} else if len(s.inbuf) == 0 || &raw[0] != &s.inbuf[0] { // NB: trick to avoid self-copy @1
			s.inbuf = append(s.inbuf[:0], raw...)
		} // otherwise there is something left, but already @ s.inbuf[0:]
	}()

	// shortcuts
	ss := &s.Stats
	mrt := &s.mrtmsg
	bgp4mp := &s.bgp4mp

	// process until raw is empty
	for len(raw) > 0 {
		// parse raw MRT message
		off, perr := mrt.Parse(raw)

		// success?
		switch perr {
		case nil:
			ss.Parsed++
			raw = raw[off:]
		case io.ErrUnexpectedEOF: // need more data
			ss.Short++
			return lenp, nil // defer will buffer raw
		default: // parse error, try to skip the garbled data
			ss.Garbled++
			if off > 0 {
				raw = raw[off:] // buffer the remainder for re-try
			} else {
				raw = nil // no idea, throw out
			}
			return lenp, perr
		}

		// parse generic MRT message as an MRT BGP4MP message
		perr = bgp4mp.Parse(mrt)
		switch perr {
		case nil:
			ss.ParsedBgp++ // success
		case ErrType, ErrSub:
			ss.ParsedSkip++
			continue
		default:
			return lenp, perr
		}

		// write BGP4MP raw data to BGP session
		_, perr = s.Bgp.Rx.WriteTime(bgp4mp.Data, bgp4mp.msg.Time)
		if perr != nil {
			return lenp, perr
		}
	}

	// exactly lenp bytes consumed and processed, no error
	return lenp, nil
}
