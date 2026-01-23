// Package bmp - Wire format tests for BMP message parsing
// Tests RFC 7854 compliance
package bmp

import (
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// ============================================================================
// Test Helper Functions
// ============================================================================

func appendUint16(dst []byte, v uint16) []byte {
	return append(dst, byte(v>>8), byte(v))
}

func appendUint32(dst []byte, v uint32) []byte {
	return append(dst, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func appendUint64(dst []byte, v uint64) []byte {
	return append(dst,
		byte(v>>56), byte(v>>48), byte(v>>40), byte(v>>32),
		byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

// makeBmpHeader creates a BMP common header (version, length, type)
func makeBmpHeader(length uint32, typ MsgType) []byte {
	buf := []byte{VERSION}
	buf = appendUint32(buf, length)
	buf = append(buf, byte(typ))
	return buf
}

// makePeerHeader creates a BMP Per-Peer Header
func makePeerHeader(peerType, flags uint8, rd uint64, addr netip.Addr, as, id uint32, sec, usec uint32) []byte {
	buf := []byte{peerType, flags}
	buf = appendUint64(buf, rd)

	// IP address (16 bytes, IPv4 in last 4 bytes)
	if addr.Is6() {
		buf = append(buf, addr.AsSlice()...)
	} else {
		// IPv4: 12 zero bytes + 4 byte address
		buf = append(buf, make([]byte, 12)...)
		buf = append(buf, addr.AsSlice()...)
	}

	buf = appendUint32(buf, as)
	buf = appendUint32(buf, id)
	buf = appendUint32(buf, sec)
	buf = appendUint32(buf, usec)
	return buf
}

// makeBgpKeepalive creates a minimal BGP KEEPALIVE message (19 bytes)
func makeBgpKeepalive() []byte {
	buf := make([]byte, 19)
	// BGP marker (16 x 0xff)
	for i := 0; i < 16; i++ {
		buf[i] = 0xff
	}
	buf[16] = 0x00 // length high
	buf[17] = 0x13 // length low (19)
	buf[18] = 0x04 // type KEEPALIVE
	return buf
}

// ============================================================================
// BMP Common Header Tests (RFC 7854 Section 4.1)
// ============================================================================

func TestBmp_FromBytes_ValidRouteMonitoring(t *testing.T) {
	bgp := makeBgpKeepalive()
	peerIP := netip.MustParseAddr("192.0.2.1")
	peer := makePeerHeader(0, 0, 0, peerIP, 65001, 0x0A000001, 1700000000, 500000)

	totalLen := uint32(HEADLEN + PEER_HEADLEN + len(bgp))
	header := makeBmpHeader(totalLen, MSG_ROUTE_MONITORING)
	raw := append(header, peer...)
	raw = append(raw, bgp...)

	b := NewBmp()
	off, err := b.FromBytes(raw)
	require.NoError(t, err)
	require.Equal(t, len(raw), off)
	require.Equal(t, uint8(VERSION), b.Version)
	require.Equal(t, totalLen, b.MsgLength)
	require.Equal(t, MSG_ROUTE_MONITORING, b.MsgType)

	// Check peer header
	require.Equal(t, uint8(0), b.Peer.Type)
	require.Equal(t, uint8(0), b.Peer.Flags)
	require.Equal(t, peerIP, b.Peer.Address)
	require.Equal(t, uint32(65001), b.Peer.AS)
	require.Equal(t, uint32(0x0A000001), b.Peer.ID)

	// Check timestamp (sec=1700000000, usec=500000)
	expectedTime := time.Unix(1700000000, 500000*1000).UTC()
	require.True(t, b.Peer.Time.Equal(expectedTime), "expected %v, got %v", expectedTime, b.Peer.Time)

	// Check BGP data extracted
	require.Equal(t, bgp, b.BgpData)
}

func TestBmp_FromBytes_ValidIPv6Peer(t *testing.T) {
	bgp := makeBgpKeepalive()
	peerIP := netip.MustParseAddr("2001:db8::1")
	// V flag set (0x80) for IPv6
	peer := makePeerHeader(0, PEER_FLAG_V, 0, peerIP, 65002, 0x0A000002, 1700000000, 0)

	totalLen := uint32(HEADLEN + PEER_HEADLEN + len(bgp))
	header := makeBmpHeader(totalLen, MSG_ROUTE_MONITORING)
	raw := append(header, peer...)
	raw = append(raw, bgp...)

	b := NewBmp()
	off, err := b.FromBytes(raw)
	require.NoError(t, err)
	require.Equal(t, len(raw), off)
	require.True(t, b.Peer.IsIPv6())
	require.Equal(t, peerIP, b.Peer.Address)
}

func TestBmp_FromBytes_ValidPeerUp(t *testing.T) {
	peerIP := netip.MustParseAddr("10.0.0.1")
	peer := makePeerHeader(0, 0, 0, peerIP, 65001, 0xC0000201, 1700000000, 0)

	// Peer Up has additional data after per-peer header (local address, ports, etc.)
	// For this test we just verify per-peer header is parsed
	peerUpData := make([]byte, 20) // placeholder for additional peer up info

	totalLen := uint32(HEADLEN + PEER_HEADLEN + len(peerUpData))
	header := makeBmpHeader(totalLen, MSG_PEER_UP)
	raw := append(header, peer...)
	raw = append(raw, peerUpData...)

	b := NewBmp()
	off, err := b.FromBytes(raw)
	require.NoError(t, err)
	require.Equal(t, len(raw), off)
	require.Equal(t, MSG_PEER_UP, b.MsgType)
	require.True(t, b.HasPerPeerHeader())
	require.Equal(t, peerIP, b.Peer.Address)
	require.Nil(t, b.BgpData) // No BGP data for Peer Up
}

func TestBmp_FromBytes_ValidPeerDown(t *testing.T) {
	peerIP := netip.MustParseAddr("10.0.0.2")
	peer := makePeerHeader(0, 0, 0, peerIP, 65001, 0xC0000201, 1700000000, 0)

	// Peer Down has reason code after per-peer header
	peerDownData := []byte{0x01} // reason = 1

	totalLen := uint32(HEADLEN + PEER_HEADLEN + len(peerDownData))
	header := makeBmpHeader(totalLen, MSG_PEER_DOWN)
	raw := append(header, peer...)
	raw = append(raw, peerDownData...)

	b := NewBmp()
	off, err := b.FromBytes(raw)
	require.NoError(t, err)
	require.Equal(t, len(raw), off)
	require.Equal(t, MSG_PEER_DOWN, b.MsgType)
	require.True(t, b.HasPerPeerHeader())
}

func TestBmp_FromBytes_ValidInitiation(t *testing.T) {
	// Initiation message has no per-peer header
	// Contains TLVs with sysDescr, sysName, etc.
	initData := []byte{
		0x00, 0x01, // Type = sysDescr
		0x00, 0x04, // Length = 4
		't', 'e', 's', 't',
	}

	totalLen := uint32(HEADLEN + len(initData))
	header := makeBmpHeader(totalLen, MSG_INITIATION)
	raw := append(header, initData...)

	b := NewBmp()
	off, err := b.FromBytes(raw)
	require.NoError(t, err)
	require.Equal(t, len(raw), off)
	require.Equal(t, MSG_INITIATION, b.MsgType)
	require.False(t, b.HasPerPeerHeader())
	require.Nil(t, b.BgpData)
	// Peer should be reset/empty for messages without per-peer header
	require.Equal(t, uint8(0), b.Peer.Type)
	require.Equal(t, uint32(0), b.Peer.AS)
}

func TestBmp_FromBytes_ValidTermination(t *testing.T) {
	// Termination message has no per-peer header
	termData := []byte{
		0x00, 0x00, // Type = string
		0x00, 0x03, // Length = 3
		'b', 'y', 'e',
	}

	totalLen := uint32(HEADLEN + len(termData))
	header := makeBmpHeader(totalLen, MSG_TERMINATION)
	raw := append(header, termData...)

	b := NewBmp()
	off, err := b.FromBytes(raw)
	require.NoError(t, err)
	require.Equal(t, len(raw), off)
	require.Equal(t, MSG_TERMINATION, b.MsgType)
	require.False(t, b.HasPerPeerHeader())
}

func TestBmp_FromBytes_ValidStatisticsReport(t *testing.T) {
	peerIP := netip.MustParseAddr("192.168.1.1")
	peer := makePeerHeader(0, 0, 0, peerIP, 65003, 0x0A0A0A01, 1700000000, 0)

	// Statistics report data (stats count + TLVs)
	statsData := appendUint32(nil, 1) // 1 stat
	statsData = appendUint16(statsData, 0)
	statsData = appendUint16(statsData, 4)
	statsData = appendUint32(statsData, 100) // stat value

	totalLen := uint32(HEADLEN + PEER_HEADLEN + len(statsData))
	header := makeBmpHeader(totalLen, MSG_STATISTICS_REPORT)
	raw := append(header, peer...)
	raw = append(raw, statsData...)

	b := NewBmp()
	off, err := b.FromBytes(raw)
	require.NoError(t, err)
	require.Equal(t, len(raw), off)
	require.Equal(t, MSG_STATISTICS_REPORT, b.MsgType)
	require.True(t, b.HasPerPeerHeader())
	require.Nil(t, b.BgpData) // Statistics Report doesn't have BGP data
}

// ============================================================================
// BMP Error Handling Tests
// ============================================================================

func TestBmp_FromBytes_InvalidVersion(t *testing.T) {
	tests := []struct {
		name    string
		version byte
	}{
		{"version 0", 0},
		{"version 1", 1},
		{"version 2", 2},
		{"version 4", 4},
		{"version 255", 255},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := makeBmpHeader(HEADLEN, MSG_INITIATION)
			raw[0] = tt.version // Override version

			b := NewBmp()
			_, err := b.FromBytes(raw)
			require.ErrorIs(t, err, ErrVersion)
		})
	}
}

func TestBmp_FromBytes_TruncatedHeader(t *testing.T) {
	tests := []struct {
		name string
		buf  []byte
	}{
		{"empty buffer", []byte{}},
		{"1 byte", []byte{VERSION}},
		{"5 bytes (missing type)", []byte{VERSION, 0, 0, 0, 6}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := NewBmp()
			_, err := b.FromBytes(tt.buf)
			require.ErrorIs(t, err, ErrShort)
		})
	}
}

func TestBmp_FromBytes_LengthExceedsBuffer(t *testing.T) {
	// Header declares 100 bytes but only 6 present
	raw := makeBmpHeader(100, MSG_INITIATION)

	b := NewBmp()
	_, err := b.FromBytes(raw)
	require.ErrorIs(t, err, ErrLength)
}

func TestBmp_FromBytes_TruncatedPeerHeader(t *testing.T) {
	// Route Monitoring with truncated peer header
	totalLen := uint32(HEADLEN + 10) // Only 10 bytes of peer header (need 42)
	raw := makeBmpHeader(totalLen, MSG_ROUTE_MONITORING)
	raw = append(raw, make([]byte, 10)...)

	b := NewBmp()
	_, err := b.FromBytes(raw)
	require.ErrorIs(t, err, ErrShort)
}

func TestBmp_FromBytes_ExtraBytes(t *testing.T) {
	// Valid message followed by extra bytes (should only parse first message)
	initData := []byte{0x00, 0x00, 0x00, 0x02, 'o', 'k'}
	totalLen := uint32(HEADLEN + len(initData))
	raw := makeBmpHeader(totalLen, MSG_INITIATION)
	raw = append(raw, initData...)
	raw = append(raw, 0xDE, 0xAD, 0xBE, 0xEF) // extra bytes

	b := NewBmp()
	off, err := b.FromBytes(raw)
	require.NoError(t, err)
	require.Equal(t, int(totalLen), off) // Should only consume declared length
}

// ============================================================================
// Peer Header Tests (RFC 7854 Section 4.2)
// ============================================================================

func TestPeer_FromBytes_Valid(t *testing.T) {
	peerIP := netip.MustParseAddr("198.51.100.1")
	raw := makePeerHeader(1, PEER_FLAG_L, 0x1234567890ABCDEF, peerIP, 4200000001, 0xC6336401, 1700000000, 123456)

	p := &Peer{}
	off, err := p.FromBytes(raw)
	require.NoError(t, err)
	require.Equal(t, PEER_HEADLEN, off)
	require.Equal(t, uint8(1), p.Type)
	require.Equal(t, uint8(PEER_FLAG_L), p.Flags)
	require.Equal(t, uint64(0x1234567890ABCDEF), p.RD)
	require.Equal(t, peerIP, p.Address)
	require.Equal(t, uint32(4200000001), p.AS)
	require.Equal(t, uint32(0xC6336401), p.ID)
	require.True(t, p.IsPostPolicy())
	require.False(t, p.IsIPv6())
	require.False(t, p.Is2ByteAS())

	// Check timestamp
	expectedTime := time.Unix(1700000000, 123456*1000).UTC()
	require.True(t, p.Time.Equal(expectedTime))
}

func TestPeer_FromBytes_IPv6(t *testing.T) {
	peerIP := netip.MustParseAddr("2001:db8:85a3::8a2e:370:7334")
	raw := makePeerHeader(0, PEER_FLAG_V, 0, peerIP, 65001, 0x01020304, 1700000000, 0)

	p := &Peer{}
	off, err := p.FromBytes(raw)
	require.NoError(t, err)
	require.Equal(t, PEER_HEADLEN, off)
	require.True(t, p.IsIPv6())
	require.Equal(t, peerIP, p.Address)
}

func TestPeer_FromBytes_AllFlags(t *testing.T) {
	peerIP := netip.MustParseAddr("2001:db8::1")
	flags := uint8(PEER_FLAG_V | PEER_FLAG_L | PEER_FLAG_A)
	raw := makePeerHeader(2, flags, 0, peerIP, 65001, 0x01020304, 1700000000, 0)

	p := &Peer{}
	_, err := p.FromBytes(raw)
	require.NoError(t, err)
	require.True(t, p.IsIPv6())
	require.True(t, p.IsPostPolicy())
	require.True(t, p.Is2ByteAS())
}

func TestPeer_FromBytes_TooShort(t *testing.T) {
	tests := []struct {
		name string
		buf  []byte
	}{
		{"empty", []byte{}},
		{"10 bytes", make([]byte, 10)},
		{"41 bytes", make([]byte, 41)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Peer{}
			_, err := p.FromBytes(tt.buf)
			require.ErrorIs(t, err, ErrShort)
		})
	}
}

// ============================================================================
// Reset and CopyData Tests
// ============================================================================

func TestBmp_Reset(t *testing.T) {
	bgp := makeBgpKeepalive()
	peerIP := netip.MustParseAddr("10.0.0.1")
	peer := makePeerHeader(0, 0, 0, peerIP, 65001, 0x0A000001, 1700000000, 0)

	totalLen := uint32(HEADLEN + PEER_HEADLEN + len(bgp))
	header := makeBmpHeader(totalLen, MSG_ROUTE_MONITORING)
	raw := append(header, peer...)
	raw = append(raw, bgp...)

	b := NewBmp()
	_, err := b.FromBytes(raw)
	require.NoError(t, err)
	require.NotNil(t, b.BgpData)

	b.Reset()
	require.Equal(t, uint8(0), b.Version)
	require.Equal(t, uint32(0), b.MsgLength)
	require.Equal(t, MsgType(0), b.MsgType)
	require.Nil(t, b.BgpData)
	require.Equal(t, uint32(0), b.Peer.AS)
}

func TestBmp_CopyData(t *testing.T) {
	bgp := makeBgpKeepalive()
	peerIP := netip.MustParseAddr("10.0.0.1")
	peer := makePeerHeader(0, 0, 0, peerIP, 65001, 0x0A000001, 1700000000, 0)

	totalLen := uint32(HEADLEN + PEER_HEADLEN + len(bgp))
	header := makeBmpHeader(totalLen, MSG_ROUTE_MONITORING)
	raw := append(header, peer...)
	raw = append(raw, bgp...)

	b := NewBmp()
	_, err := b.FromBytes(raw)
	require.NoError(t, err)

	// BgpData should reference original buffer
	originalData := b.BgpData

	// CopyData should make an independent copy
	b.CopyData()
	require.Equal(t, originalData, b.BgpData)

	// Modify original buffer - BgpData should be unaffected after CopyData
	raw[len(raw)-1] = 0x00
	require.Equal(t, byte(0x04), b.BgpData[len(b.BgpData)-1]) // Still original value
}

func TestPeer_Reset(t *testing.T) {
	peerIP := netip.MustParseAddr("10.0.0.1")
	raw := makePeerHeader(1, PEER_FLAG_V|PEER_FLAG_L, 0x1234, peerIP, 65001, 0x0A000001, 1700000000, 500)

	p := &Peer{}
	_, err := p.FromBytes(raw)
	require.NoError(t, err)
	require.Equal(t, uint32(65001), p.AS)

	p.Reset()
	require.Equal(t, uint8(0), p.Type)
	require.Equal(t, uint8(0), p.Flags)
	require.Equal(t, uint64(0), p.RD)
	require.False(t, p.Address.IsValid())
	require.Equal(t, uint32(0), p.AS)
	require.Equal(t, uint32(0), p.ID)
	require.True(t, p.Time.IsZero())
}

// ============================================================================
// MsgType Tests
// ============================================================================

func TestMsgType_String(t *testing.T) {
	tests := []struct {
		typ  MsgType
		want string
	}{
		{MSG_ROUTE_MONITORING, "ROUTE_MONITORING"},
		{MSG_STATISTICS_REPORT, "STATISTICS_REPORT"},
		{MSG_PEER_DOWN, "PEER_DOWN"},
		{MSG_PEER_UP, "PEER_UP"},
		{MSG_INITIATION, "INITIATION"},
		{MSG_TERMINATION, "TERMINATION"},
		{MSG_ROUTE_MIRRORING, "ROUTE_MIRRORING"},
		{MsgType(99), "UNKNOWN"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			require.Equal(t, tt.want, tt.typ.String())
		})
	}
}

func TestBmp_HasPerPeerHeader(t *testing.T) {
	tests := []struct {
		typ  MsgType
		want bool
	}{
		{MSG_ROUTE_MONITORING, true},
		{MSG_STATISTICS_REPORT, true},
		{MSG_PEER_DOWN, true},
		{MSG_PEER_UP, true},
		{MSG_INITIATION, false},
		{MSG_TERMINATION, false},
		{MSG_ROUTE_MIRRORING, false},
	}

	for _, tt := range tests {
		t.Run(tt.typ.String(), func(t *testing.T) {
			b := &Bmp{MsgType: tt.typ}
			require.Equal(t, tt.want, b.HasPerPeerHeader())
		})
	}
}
