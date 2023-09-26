package mrt

import (
	"compress/bzip2"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/bgpfix/bgpfix/pipe"
	"github.com/rs/zerolog"
)

// Reader reads MRT-BGP4MP messages into a pipe.Direction.
type Reader struct {
	zerolog.Logger

	ctx    context.Context
	cancel context.CancelCauseFunc

	Pipe  *pipe.Pipe      // target pipe
	Dir   *pipe.Direction // target direction
	Stats ReaderStats     // our stats

	ibuf []byte // input buffer
	mrt  Mrt    // raw MRT message
	bm   BgpMsg // MRT-BGP message
}

// BGP reader statistics
type ReaderStats struct {
	Parsed     uint64 // parsed messages (total)
	ParsedBgp  uint64 // parsed BGP4MP messages
	ParsedSkip uint64 // skipped non-BGP4MP messages
	Short      uint64 // data in buffer too short, should retry
	Garbled    uint64 // parse error
}

// NewReader returns a new Reader for given pipe.Direction.
func NewReader(ctx context.Context, log *zerolog.Logger, dst *pipe.Direction) *Reader {
	br := &Reader{}
	br.ctx, br.cancel = context.WithCancelCause(ctx)
	if log != nil {
		br.Logger = *log
	} else {
		br.Logger = zerolog.Nop()
	}
	br.Dir = dst
	br.Pipe = dst.Pipe
	return br
}

// Write implements io.Writer and reads all MRT-BGP4MP messages from src
// into br.Direction. Must not be used concurrently.
func (br *Reader) Write(src []byte) (n int, err error) {
	var (
		bs  = &br.Stats
		mrt = &br.mrt
		bm  = &br.bm
	)

	// context check
	if br.ctx.Err() != nil {
		return 0, context.Cause(br.ctx)
	}

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
		off, perr := mrt.Reset().Parse(raw)
		switch perr {
		case nil:
			bs.Parsed++
			raw = raw[off:]
		case io.ErrUnexpectedEOF: // need more data
			bs.Short++
			return n, nil // defer will buffer raw
		default: // parse error, try to skip the garbled data
			bs.Garbled++
			if off > 0 {
				raw = raw[off:] // buffer the remainder for re-try
			} else {
				raw = nil // no idea, throw out
			}
			return n, fmt.Errorf("MRT: %w", perr)
		}

		// parse as MRT-BGP4MP
		perr = bm.Reset().Parse(mrt)
		switch perr {
		case nil:
			bs.ParsedBgp++ // success
		case ErrType, ErrSub:
			bs.ParsedSkip++
			continue
		default:
			return n, fmt.Errorf("BGP4MP: %w", perr)
		}

		// parse as a raw BGP message
		m := br.Pipe.Get(0)
		off, perr = m.Parse(bm.Data)
		switch {
		case perr != nil:
			return n, fmt.Errorf("BGP: %w", perr)
		case off != len(bm.Data):
			return n, fmt.Errorf("BGP: %w", ErrLength)
		}

		// sail!
		m.Time = mrt.Time // use MRT time
		if err := br.Dir.WriteMsg(m); err != nil {
			return n, fmt.Errorf("pipe: %w", err)
		}
	}

	// exactly n bytes consumed and processed, no error
	return n, nil
}

// ReadFromPath opens and reads fpath into br, uncompressing if needed.
func (br *Reader) ReadFromPath(fpath string) (n int64, err error) {
	fh, err := os.Open(fpath)
	if err != nil {
		return 0, err
	}
	defer fh.Close()

	// transparent uncompress?
	var rd io.Reader
	switch filepath.Ext(fpath) {
	case ".bz2":
		rd = bzip2.NewReader(fh)
	case ".gz":
		rd, err = gzip.NewReader(fh)
		if err != nil {
			return 0, err
		}
	default:
		rd = fh
	}

	// copy all from MRT to pipe, in 10MiB steps
	buf := make([]byte, 10*1024*1024)
	return io.CopyBuffer(br, rd, buf)
}
