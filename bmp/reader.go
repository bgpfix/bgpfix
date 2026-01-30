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

	ibuf []byte   // input buffer
	bmp  *Bmp     // reusable BMP parser
	obmp *OpenBmp // reusable OpenBMP parser (for wrapped format)

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
		pipe: p,
		in:   input,
		bmp:  NewBmp(),
		obmp: NewOpenBmp(),
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
			br.obmp.Reset()
			off, perr = br.obmp.FromBytes(raw)
			if perr == nil {
				bmpData = br.obmp.Data
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
		if br.bmp.Type != MSG_ROUTE_MONITORING || len(br.bmp.BgpData) == 0 {
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

		// Set message metadata
		br.setMeta(m, br.bmp, br.obmp)

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
// References bytes in buf. Can be used concurrently.
// bmp_msg and obmp_msg may be nil, in which case new instances are created.
func (br *Reader) FromBytes(buf []byte, bgp_msg *msg.Msg, bmp_msg *Bmp, obmp_msg *OpenBmp) (n int, err error) {
	// parse OpenBMP wrapper first?
	var data []byte
	if br.OpenBMP {
		if obmp_msg == nil {
			obmp_msg = NewOpenBmp()
		} else {
			obmp_msg.Reset()
		}

		n, err = obmp_msg.FromBytes(buf)
		if err != nil {
			return n, fmt.Errorf("OpenBMP: %w", err)
		}
		data = obmp_msg.Data
	} else {
		data = buf
		n = len(buf)
	}

	// parse BMP message
	if bmp_msg == nil {
		bmp_msg = NewBmp()
	} else {
		bmp_msg.Reset()
	}
	if _, err = bmp_msg.FromBytes(data); err != nil {
		return n, fmt.Errorf("BMP: %w", err)
	}

	// only Route Monitoring messages have BGP data
	if bmp_msg.Type != MSG_ROUTE_MONITORING {
		return n, ErrNotRouteMonitoring
	}

	// parse BGP message
	if k, err := bgp_msg.FromBytes(bmp_msg.BgpData); err != nil {
		return n, fmt.Errorf("BGP: %w", err)
	} else if k != len(bmp_msg.BgpData) {
		return n, fmt.Errorf("BGP: dangling bytes %d/%d", k, len(bmp_msg.BgpData))
	}

	// set message metadata
	br.setMeta(bgp_msg, bmp_msg, obmp_msg)

	return n, nil
}

// setMeta sets message time and tags from BMP and OpenBMP headers
func (br *Reader) setMeta(m *msg.Msg, bmp *Bmp, obmp *OpenBmp) {
	m.Time = bmp.Peer.Time

	if br.NoTags {
		return
	}

	tags := pipe.UseTags(m)
	tags["PEER_IP"] = bmp.Peer.Address.String()
	tags["PEER_AS"] = strconv.FormatUint(uint64(bmp.Peer.AS), 10)

	// Add OpenBMP metadata if available
	if br.OpenBMP && obmp != nil {
		if obmp.CollectorName != "" {
			tags["COLLECTOR"] = obmp.CollectorName
		}
		if obmp.RouterName != "" {
			tags["ROUTER"] = obmp.RouterName
		} else if obmp.RouterIP.IsValid() && !obmp.RouterIP.IsUnspecified() {
			tags["ROUTER"] = obmp.RouterIP.String()
		}
	}
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
