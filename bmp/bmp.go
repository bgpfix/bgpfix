// Package bmp supports BGP Monitoring Protocol (RFC 7854)
package bmp

import (
	"bytes"
	"io"
	"net/netip"
	"strconv"

	"github.com/bgpfix/bgpfix/binary"
	"github.com/bgpfix/bgpfix/msg"
	"github.com/bgpfix/bgpfix/pipe"
)

var msb = binary.Msb

// BMP common header length (RFC 7854 section 4.1)
const HEADLEN = 6 // version(1) + length(4) + type(1)

// BMP protocol version
const VERSION = 3

// MsgType represents BMP message type (RFC 7854 section 4.1)
type MsgType uint8

const (
	MSG_ROUTE_MONITORING  MsgType = 0 // Route Monitoring
	MSG_STATISTICS_REPORT MsgType = 1 // Statistics Report
	MSG_PEER_DOWN         MsgType = 2 // Peer Down Notification
	MSG_PEER_UP           MsgType = 3 // Peer Up Notification
	MSG_INITIATION        MsgType = 4 // Initiation Message
	MSG_TERMINATION       MsgType = 5 // Termination Message
	MSG_ROUTE_MIRRORING   MsgType = 6 // Route Mirroring
)

// String returns the name of the message type
func (t MsgType) String() string {
	switch t {
	case MSG_ROUTE_MONITORING:
		return "ROUTE_MONITORING"
	case MSG_STATISTICS_REPORT:
		return "STATISTICS_REPORT"
	case MSG_PEER_DOWN:
		return "PEER_DOWN"
	case MSG_PEER_UP:
		return "PEER_UP"
	case MSG_INITIATION:
		return "INITIATION"
	case MSG_TERMINATION:
		return "TERMINATION"
	case MSG_ROUTE_MIRRORING:
		return "ROUTE_MIRRORING"
	default:
		return "UNKNOWN"
	}
}

// Bmp represents a BMP message (RFC 7854)
type Bmp struct {
	ref bool   // true iff Data is a reference to borrowed memory
	buf []byte // internal buffer

	Version uint8   // BMP version (should be 3)
	Length  uint32  // Total message length
	Type    MsgType // Message type

	Peer    Peer   // Per-Peer Header (for types 0,1,2,3)
	BgpData []byte // raw BGP message (for Route Monitoring)
}

// NewBmp returns a new empty BMP message
func NewBmp() *Bmp {
	return new(Bmp)
}

// Reset clears the message
func (b *Bmp) Reset() *Bmp {
	b.ref = false
	if cap(b.buf) < 1024*1024 {
		b.buf = b.buf[:0]
	} else {
		b.buf = nil
	}

	b.Version = 0
	b.Length = 0
	b.Type = 0
	b.Peer.Reset()
	b.BgpData = nil

	return b
}

// FromBytes parses the BMP message from raw bytes.
// Does not copy data. Returns the number of bytes consumed.
func (b *Bmp) FromBytes(raw []byte) (int, error) {
	if len(raw) < HEADLEN {
		return 0, ErrShort
	}

	// Parse common header
	b.Version = raw[0]
	if b.Version != VERSION {
		return 0, ErrVersion
	}
	b.Length = msb.Uint32(raw[1:5])
	b.Type = MsgType(raw[5])

	// Validate length
	off := HEADLEN
	ml := int(b.Length)
	if ml < off {
		return 0, ErrLength
	} else if len(raw) < ml {
		return 0, ErrShort
	}

	// Parse Per-Peer header for applicable message types
	switch b.Type {
	case MSG_ROUTE_MONITORING, MSG_STATISTICS_REPORT, MSG_PEER_DOWN, MSG_PEER_UP, MSG_ROUTE_MIRRORING:
		if ml-off < PEER_HEADLEN {
			return off, ErrShort
		}
		n, err := b.Peer.FromBytes(raw[off:])
		if err != nil {
			return off, err
		}
		off += n
	default:
		b.Peer.Reset()
	}

	// Extract BGP data for Route Monitoring messages
	if b.Type == MSG_ROUTE_MONITORING && off < ml {
		b.ref = true
		b.BgpData = raw[off:ml]
	} else {
		b.BgpData = nil
	}

	return ml, nil
}

// CopyData copies referenced data if needed, making Bmp the owner
func (b *Bmp) CopyData() *Bmp {
	if !b.ref {
		return b
	}
	b.ref = false

	if b.BgpData == nil {
		return b
	}

	b.buf = append(b.buf[:0], b.BgpData...)
	b.BgpData = b.buf
	return b
}

// HasPerPeerHeader returns true if this message type has a Per-Peer header
func (b *Bmp) HasPerPeerHeader() bool {
	switch b.Type {
	case MSG_ROUTE_MONITORING, MSG_STATISTICS_REPORT, MSG_PEER_DOWN, MSG_PEER_UP, MSG_ROUTE_MIRRORING:
		return true
	default:
		return false
	}
}

// Marshal serializes the BMP message to b.buf.
// For Route Monitoring messages, BgpData must already contain the BGP message.
func (b *Bmp) Marshal() error {
	if b.BgpData == nil && b.Type == MSG_ROUTE_MONITORING {
		return ErrNoData
	}

	// calculate total length
	length := HEADLEN
	if b.HasPerPeerHeader() {
		length += PEER_HEADLEN
	}
	length += len(b.BgpData)

	// allocate buffer
	if cap(b.buf) < length {
		b.buf = make([]byte, length)
	}
	b.buf = b.buf[:length]

	// common header
	b.buf[0] = VERSION
	msb.PutUint32(b.buf[1:5], uint32(length))
	b.buf[5] = byte(b.Type)

	off := HEADLEN

	// per-peer header
	if b.HasPerPeerHeader() {
		b.Peer.ToBytes(b.buf[off:])
		off += PEER_HEADLEN
	}

	// bgp data
	if len(b.BgpData) > 0 {
		copy(b.buf[off:], b.BgpData)
	}

	b.Length = uint32(length)
	return nil
}

// WriteTo writes the BMP message to w, implementing io.WriterTo.
// Call Marshal() first.
func (b *Bmp) WriteTo(w io.Writer) (int64, error) {
	if len(b.buf) == 0 {
		return 0, ErrNoData
	}
	n, err := w.Write(b.buf)
	return int64(n), err
}

// Bytes returns the marshaled BMP message.
// Call Marshal() first.
func (b *Bmp) Bytes() []byte {
	return b.buf
}

// FromMsg populates BMP ROUTE_MONITORING from BGP message m.
// m must already be marshaled. Extracts peer info from message tags.
func (b *Bmp) FromMsg(m *msg.Msg) error {
	if m.Data == nil {
		return ErrNoData
	}

	// Set message type
	b.Type = MSG_ROUTE_MONITORING

	// Write complete BGP message (header + data) to BgpData
	var bb bytes.Buffer
	if _, err := m.WriteTo(&bb); err != nil {
		return err
	}
	b.BgpData = bb.Bytes()

	// Set peer time from message
	b.Peer.Time = m.Time

	// Extract peer info from message tags
	if tags := pipe.GetTags(m); len(tags) > 0 {
		if s := tags["PEER_IP"]; len(s) > 0 {
			if addr, err := netip.ParseAddr(s); err == nil {
				b.Peer.Address = addr
				if addr.Is6() {
					b.Peer.Flags |= PEER_FLAG_V6
				}
			}
		}
		if s := tags["PEER_AS"]; len(s) > 0 {
			if v, err := strconv.ParseUint(s, 10, 32); err == nil {
				b.Peer.AS = uint32(v)
			}
		}
	}

	return nil
}
