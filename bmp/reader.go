package bmp

import (
	"fmt"
	"io"
	"strconv"

	"github.com/bgpfix/bgpfix/msg"
	"github.com/bgpfix/bgpfix/pipe"
)

// Reader reads BMP messages into a pipe.Input.
// Supports both raw BMP and OpenBMP-wrapped formats.
type Reader struct {
	pipe *pipe.Pipe  // target pipe
	in   *pipe.Input // target input

	ibuf    []byte   // input buffer
	bmp     *Bmp     // reusable BMP parser
	openBmp *OpenBmp // reusable OpenBMP parser (for wrapped format)

	OpenBMP bool        // true if reading OpenBMP-wrapped format
	NoTags  bool        // ignore message tags?
	Stats   ReaderStats // our stats
}

// ReaderStats holds reader statistics
type ReaderStats struct {
	Parsed     uint64 // parsed messages (total)
	ParsedBgp  uint64 // parsed BGP messages from BMP
	ParsedSkip uint64 // skipped non-Route-Monitoring messages
	Short      uint64 // data in buffer too short, should retry
	Garbled    uint64 // parse error
}

// NewReader returns a new Reader with given target Input.
func NewReader(p *pipe.Pipe, input *pipe.Input) *Reader {
	return &Reader{
		pipe:    p,
		in:      input,
		bmp:     NewBmp(),
		openBmp: NewOpenBmp(),
	}
}

// Write implements io.Writer and reads all BMP messages from src
// into the target Input. Must not be used concurrently.
func (br *Reader) Write(src []byte) (n int, err error) {
	return br.WriteFunc(src, nil)
}

// WriteFunc is the same as Write(), but takes an optional callback function
// to be called just before the message is accepted for processing. If the callback
// returns false, the message is silently dropped instead.
func (br *Reader) WriteFunc(src []byte, cb pipe.CallbackFunc) (n int, err error) {
	p := br.pipe
	stats := &br.Stats

	// append src and switch to inbuf if needed
	n = len(src) // NB: always return n=len(src)
	raw := src
	if len(br.ibuf) > 0 {
		br.ibuf = append(br.ibuf, src...)
		raw = br.ibuf
	}

	// on return, leave remainder at start of br.inbuf
	defer func() {
		if len(raw) == 0 {
			br.ibuf = br.ibuf[:0]
		} else if len(br.ibuf) == 0 || &raw[0] != &br.ibuf[0] {
			br.ibuf = append(br.ibuf[:0], raw...)
		}
	}()

	// process until raw is empty
	for len(raw) > 0 {
		var bmpData []byte
		var off int
		var perr error

		if br.OpenBMP {
			// Parse OpenBMP header first
			br.openBmp.Reset()
			off, perr = br.openBmp.FromBytes(raw)
			if perr == nil {
				bmpData = br.openBmp.Data
			}
		} else {
			// Parse raw BMP directly
			br.bmp.Reset()
			off, perr = br.bmp.FromBytes(raw)
		}

		switch perr {
		case nil:
			stats.Parsed++
			raw = raw[off:]
		case ErrShort:
			stats.Short++
			return n, nil // defer will buffer raw
		default:
			stats.Garbled++
			if off > 0 {
				raw = raw[off:]
			} else {
				raw = nil
			}
			return n, fmt.Errorf("BMP: %w", perr)
		}

		// If OpenBMP, need to parse the inner BMP message
		if br.OpenBMP {
			br.bmp.Reset()
			if _, perr = br.bmp.FromBytes(bmpData); perr != nil {
				stats.Garbled++
				return n, fmt.Errorf("BMP: %w", perr)
			}
		}

		// Only process Route Monitoring messages with BGP data
		if br.bmp.MsgType != MSG_ROUTE_MONITORING || len(br.bmp.BgpData) == 0 {
			stats.ParsedSkip++
			continue
		}
		stats.ParsedBgp++

		// Parse BGP message
		m := p.GetMsg()
		switch k, perr := m.FromBytes(br.bmp.BgpData); {
		case perr != nil:
			p.PutMsg(m)
			stats.Garbled++
			return n, fmt.Errorf("BGP: %w", perr)
		case k != len(br.bmp.BgpData):
			p.PutMsg(m)
			stats.Garbled++
			return n, fmt.Errorf("BGP: dangling bytes %d/%d", k, len(br.bmp.BgpData))
		}

		// Set message time from BMP peer header
		m.Time = br.bmp.Peer.Time

		// Add tags from BMP peer header
		if !br.NoTags {
			tags := pipe.UseContext(m).UseTags()
			tags["PEER_IP"] = br.bmp.Peer.Address.String()
			tags["PEER_AS"] = strconv.FormatUint(uint64(br.bmp.Peer.AS), 10)

			// Add OpenBMP metadata if available
			if br.OpenBMP {
				if br.openBmp.CollectorName != "" {
					tags["COLLECTOR"] = br.openBmp.CollectorName
				}
				if br.openBmp.RouterName != "" {
					tags["ROUTER"] = br.openBmp.RouterName
				} else if br.openBmp.RouterIP.IsValid() {
					tags["ROUTER"] = br.openBmp.RouterIP.String()
				}
			}
		}

		// Callback check
		if cb != nil && !cb(m) {
			p.PutMsg(m)
			continue
		}

		// Write to pipe
		m.CopyData()
		if err := br.in.WriteMsg(m); err != nil {
			return n, fmt.Errorf("pipe: %w", err)
		}
	}

	return n, nil
}

// FromBytes parses the first BMP message in buf and references it in bgp_msg.
// Does not buffer or copy buf. Can be used concurrently.
func (br *Reader) FromBytes(buf []byte, bgp_msg *msg.Msg) (n int, err error) {
	bmp := NewBmp()
	var bmpData []byte

	if br.OpenBMP {
		openBmp := NewOpenBmp()
		n, err = openBmp.FromBytes(buf)
		if err != nil {
			return n, fmt.Errorf("OpenBMP: %w", err)
		}
		bmpData = openBmp.Data
	} else {
		bmpData = buf
		n = len(buf)
	}

	if _, err = bmp.FromBytes(bmpData); err != nil {
		return n, fmt.Errorf("BMP: %w", err)
	}

	// Only Route Monitoring messages have BGP data
	if bmp.MsgType != MSG_ROUTE_MONITORING {
		return n, ErrNotRouteMonitoring
	}
	if len(bmp.BgpData) == 0 {
		return n, ErrNoBgpData
	}

	// Parse BGP message
	if k, err := bgp_msg.FromBytes(bmp.BgpData); err != nil {
		return n, fmt.Errorf("BGP: %w", err)
	} else if k != len(bmp.BgpData) {
		return n, fmt.Errorf("BGP: dangling bytes %d/%d", k, len(bmp.BgpData))
	}

	// Set time from BMP peer header
	bgp_msg.Time = bmp.Peer.Time

	return n, nil
}

// ReadFrom implements io.ReaderFrom, reading BMP messages from r until EOF.
func (br *Reader) ReadFrom(r io.Reader) (n int64, err error) {
	buf := make([]byte, 64*1024)
	for {
		k, rerr := r.Read(buf)
		n += int64(k)
		if k > 0 {
			if _, err = br.Write(buf[:k]); err != nil {
				return n, err
			}
		}
		if rerr == io.EOF {
			return n, nil
		}
		if rerr != nil {
			return n, rerr
		}
	}
}
