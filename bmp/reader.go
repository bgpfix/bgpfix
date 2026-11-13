package bmp

import (
	"fmt"
	"io"
	"time"

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

	peers   map[peerKey]*peerState // per-peer state
	lastkey peerKey                // key of lastps
	lastps  *peerState             // last peer looked up
	Router  string                 // router name for the ROUTER tag; set from the Initiation sysName

	OpenBMP bool        // true if reading OpenBMP-wrapped format
	Session bool        // emit Peer Up as OPENs and Peer Down as NOTIFICATION?
	NoTags  bool        // ignore message tags?
	Stats   ReaderStats // our stats
}

// ReaderStats holds reader statistics
type ReaderStats struct {
	Parsed     uint64 // parsed messages (total)
	ParsedBgp  uint64 // parsed BGP messages from BMP
	ParsedSkip uint64 // skipped non-Route-Monitoring messages
	PeerUp     uint64 // Peer Up notifications
	PeerDown   uint64 // Peer Down notifications
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

		// Route Monitoring: the hot path
		if br.bmp.Type == MSG_ROUTE_MONITORING {
			if len(br.bmp.BgpData) == 0 {
				stats.ParsedSkip++
			} else if err := br.emit(br.bmp.BgpData, false, cb); err != nil {
				return n, err
			}
			continue
		}

		// other types: track the session state, maybe emit BGP messages
		bgps := br.track(br.bmp)
		if len(bgps) == 0 {
			stats.ParsedSkip++
		}
		for i, bgp := range bgps {
			if err := br.emit(bgp, br.bmp.Type == MSG_PEER_UP && i == 0, cb); err != nil {
				return n, err
			}
		}
	}

	return n, nil
}

// emit parses BGP message bgp from br.bmp and writes it to the pipe input
func (br *Reader) emit(bgp []byte, sent bool, cb pipe.CallbackFunc) error {
	p, stats := br.pipe, &br.Stats
	stats.ParsedBgp++

	// parse BGP message
	m := p.GetMsg()
	switch k, perr := m.FromBytes(bgp); {
	case perr != nil:
		p.PutMsg(m)
		stats.Garbled++
		return fmt.Errorf("BGP: %w", perr)
	case k != len(bgp):
		p.PutMsg(m)
		stats.Garbled++
		return fmt.Errorf("BGP: dangling bytes %d/%d", k, len(bgp))
	}

	// set message metadata, using the per-peer cache
	br.setMeta(m, br.bmp, br.obmp, br.peer(&br.bmp.Peer, !br.NoTags))
	if sent && !br.NoTags {
		pipe.UseTags(m)["BMP_OPEN"] = "sent" // the OPEN sent by the monitored router
	}

	// callback check
	if cb != nil && !cb(m) {
		p.PutMsg(m)
		return nil
	}

	// write to pipe
	m.CopyData()
	if err := br.in.WriteMsg(m); err != nil {
		return fmt.Errorf("pipe: %w", err)
	}
	return nil
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
	} else if bmp_msg.BgpData == nil {
		return n, ErrNoData
	}

	// parse BGP message
	if k, err := bgp_msg.FromBytes(bmp_msg.BgpData); err != nil {
		return n, fmt.Errorf("BGP: %w", err)
	} else if k != len(bmp_msg.BgpData) {
		return n, fmt.Errorf("BGP: dangling bytes %d/%d", k, len(bmp_msg.BgpData))
	}

	// set message metadata
	// NB: no per-peer state, as it would need a lock
	br.setMeta(bgp_msg, bmp_msg, obmp_msg, nil)

	return n, nil
}

// setMeta sets message time and tags from BMP and OpenBMP headers.
// ps is the per-peer state, if any.
func (br *Reader) setMeta(m *msg.Msg, bmp *Bmp, obmp *OpenBmp, ps *peerState) {
	m.Time = bmp.Peer.Time
	if m.Time.Unix() == 0 {
		m.Time = time.Now().UTC() // NB: zero means the time is not available (RFC 7854/4.2)
	}

	// the peer A flag determines the AS_PATH encoding (RFC 7854/4.2),
	// possibly overriding session capabilities in parsers
	if bmp.Peer.Is2ByteAS() {
		m.ParseAS4 = -1
	} else {
		m.ParseAS4 = 1
	}

	// ADD-PATH is negotiated in the OPENs carried by Peer Up
	// NB: unknown peer (no Peer Up seen, eg. a Kafka feed) means no data
	// NB: negotiated per address family, so a peer may have it on IPv4 only
	if ps != nil && ps.up {
		on := ps.addpathIn
		if bmp.Peer.IsAdjRibOut() {
			on = ps.addpathOut
		}
		if on != nil {
			m.AddPath = on
		} else {
			m.ParseAddPath = -1
		}
	}

	if br.NoTags {
		return
	}

	// NB: format the peer tags once per peer, not per message
	if ps == nil {
		ps = new(peerState)
	}
	if ps.ip == "" || ps.as != bmp.Peer.AS || ps.id != bmp.Peer.ID {
		ps.setTags(&bmp.Peer)
	}

	tags := pipe.UseTags(m)
	tags["PEER_IP"] = ps.ip
	tags["PEER_AS"] = ps.asn
	if ps.bgpid != "" {
		tags["PEER_ID"] = ps.bgpid
	}
	if rib := bmp.Peer.Rib(); rib != "in-pre" {
		tags["BMP_RIB"] = rib // NB: the default (pre-policy Adj-RIB-In) is not tagged
	}
	if ps.rd != "" {
		tags["PEER_RD"] = ps.rd
	}
	if br.Router != "" {
		tags["ROUTER"] = br.Router
	}

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
