package bmp

import (
	"net/netip"
	"time"
)

// Per-Peer header length (RFC 7854 section 4.2)
const PEER_HEADLEN = 42

// Peer represents BMP Per-Peer Header (RFC 7854 section 4.2)
type Peer struct {
	Type    uint8      // Peer Type (0=Global, 1=RD, 2=Local, 3=Loc-RIB)
	Flags   uint8      // Peer Flags
	RD      uint64     // Peer Distinguisher (Route Distinguisher for type 1)
	Address netip.Addr // Peer IP Address
	AS      uint32     // Peer AS Number
	ID      uint32     // Peer BGP ID
	Time    time.Time  // Timestamp
}

// Peer Types (https://www.iana.org/assignments/bmp-parameters/)
const (
	PEER_TYPE_GLOBAL  uint8 = 0 // Global Instance Peer
	PEER_TYPE_RD      uint8 = 1 // RD Instance Peer
	PEER_TYPE_LOCAL   uint8 = 2 // Local Instance Peer
	PEER_TYPE_LOC_RIB uint8 = 3 // Loc-RIB Instance Peer (RFC 9069)
)

// Peer Flags (RFC 7854 section 4.2, RFC 8671)
const (
	PEER_FLAG_V6 = 0x80 // V flag: IPv6 (1) or IPv4 (0)
	PEER_FLAG_L  = 0x40 // L flag: post-policy (1) or pre-policy (0)
	PEER_FLAG_A  = 0x20 // A flag: legacy 2-byte AS path format (1) or 4-byte AS (0)
	PEER_FLAG_O  = 0x10 // O flag: Adj-RIB-Out (1) or Adj-RIB-In (0) (RFC 8671)
)

// Reset clears the peer header
func (p *Peer) Reset() {
	p.Type = 0
	p.Flags = 0
	p.RD = 0
	p.Address = netip.Addr{}
	p.AS = 0
	p.ID = 0
	p.Time = time.Time{}
}

// IsIPv6 returns true if peer address is IPv6
func (p *Peer) IsIPv6() bool {
	return p.Flags&PEER_FLAG_V6 != 0
}

// IsPostPolicy returns true if this is post-policy data
func (p *Peer) IsPostPolicy() bool {
	return p.Flags&PEER_FLAG_L != 0
}

// Is2ByteAS returns true if AS is 2-byte (legacy)
func (p *Peer) Is2ByteAS() bool {
	return p.Flags&PEER_FLAG_A != 0
}

// IsAdjRibOut returns true if this is Adj-RIB-Out data (RFC 8671)
func (p *Peer) IsAdjRibOut() bool {
	return p.Flags&PEER_FLAG_O != 0
}

// IsLocRib returns true if peer type is Loc-RIB Instance (RFC 9069)
func (p *Peer) IsLocRib() bool {
	return p.Type == PEER_TYPE_LOC_RIB
}

// ToBytes serializes the Per-Peer header to dst, returning the result.
// dst should have capacity for at least PEER_HEADLEN bytes.
func (p *Peer) ToBytes(dst []byte) []byte {
	if cap(dst) < PEER_HEADLEN {
		dst = make([]byte, PEER_HEADLEN)
	}
	dst = dst[:PEER_HEADLEN]

	dst[0] = p.Type
	dst[1] = p.Flags
	msb.PutUint64(dst[2:10], p.RD)

	// IP address (16 bytes, IPv4 in last 4)
	clear(dst[10:26])
	if p.Address.IsValid() {
		if p.Flags&PEER_FLAG_V6 != 0 {
			copy(dst[10:26], p.Address.AsSlice())
		} else {
			copy(dst[22:26], p.Address.AsSlice())
		}
	}

	msb.PutUint32(dst[26:30], p.AS)
	msb.PutUint32(dst[30:34], p.ID)

	// timestamp
	sec := p.Time.Unix()
	usec := p.Time.UnixMicro() % 1e6
	msb.PutUint32(dst[34:38], uint32(sec))
	msb.PutUint32(dst[38:42], uint32(usec))

	return dst
}

// FromBytes parses the Per-Peer header from raw bytes.
// Returns the number of bytes consumed.
func (p *Peer) FromBytes(raw []byte) (int, error) {
	if len(raw) < PEER_HEADLEN {
		return 0, ErrShort
	}

	p.Type = raw[0]
	p.Flags = raw[1]
	p.RD = msb.Uint64(raw[2:10])

	// Parse IP address (16 bytes, IPv4 is in last 4 bytes)
	if p.Flags&PEER_FLAG_V6 != 0 {
		// IPv6
		p.Address = netip.AddrFrom16([16]byte(raw[10:26]))
	} else {
		// IPv4 (stored in last 4 bytes of 16-byte field)
		p.Address = netip.AddrFrom4([4]byte(raw[22:26]))
	}

	p.AS = msb.Uint32(raw[26:30])
	p.ID = msb.Uint32(raw[30:34])

	// Timestamp: seconds + microseconds
	sec := msb.Uint32(raw[34:38])
	usec := msb.Uint32(raw[38:42])
	p.Time = time.Unix(int64(sec), int64(usec)*1000).UTC()

	return PEER_HEADLEN, nil
}
