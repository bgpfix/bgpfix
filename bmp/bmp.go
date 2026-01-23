// Package bmp supports BGP Monitoring Protocol (RFC 7854)
package bmp

import (
	"github.com/bgpfix/bgpfix/binary"
)

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

	Version   uint8   // BMP version (should be 3)
	MsgLength uint32  // Total message length
	MsgType   MsgType // Message type

	Peer    Peer   // Per-Peer Header (for types 0,1,2,3)
	BgpData []byte // Extracted BGP message data (for Route Monitoring)
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
	b.MsgLength = 0
	b.MsgType = 0
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

	msb := binary.Msb

	// Parse common header
	b.Version = raw[0]
	if b.Version != VERSION {
		return 0, ErrVersion
	}

	b.MsgLength = msb.Uint32(raw[1:5])
	b.MsgType = MsgType(raw[5])

	// Validate length
	if int(b.MsgLength) > len(raw) {
		return 0, ErrLength
	}

	off := HEADLEN
	msgEnd := int(b.MsgLength)

	// Parse Per-Peer header for applicable message types
	switch b.MsgType {
	case MSG_ROUTE_MONITORING, MSG_STATISTICS_REPORT, MSG_PEER_DOWN, MSG_PEER_UP:
		if len(raw[off:]) < PEER_HEADLEN {
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
	if b.MsgType == MSG_ROUTE_MONITORING && off < msgEnd {
		b.ref = true
		b.BgpData = raw[off:msgEnd]
	} else {
		b.BgpData = nil
	}

	return msgEnd, nil
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
	switch b.MsgType {
	case MSG_ROUTE_MONITORING, MSG_STATISTICS_REPORT, MSG_PEER_DOWN, MSG_PEER_UP:
		return true
	default:
		return false
	}
}
