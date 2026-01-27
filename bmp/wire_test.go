// Package bmp - Wire format tests for BMP message parsing
// Tests RFC 7854 compliance
package bmp

// Some test data in this file is derived from routecore (https://github.com/NLnetLabs/routecore)
// Copyright (c) 2021, NLnet Labs. All rights reserved.
// Licensed under the BSD 3-Clause License.
// See https://github.com/NLnetLabs/routecore/blob/main/LICENSE

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
		{MSG_ROUTE_MIRRORING, true}, // RFC 7854 section 4.7
	}

	for _, tt := range tests {
		t.Run(tt.typ.String(), func(t *testing.T) {
			b := &Bmp{MsgType: tt.typ}
			require.Equal(t, tt.want, b.HasPerPeerHeader())
		})
	}
}

// ============================================================================
// OpenBMP Tests
// ============================================================================

// makeOpenBmpHeader creates a minimal OpenBMP header (14 bytes)
func makeOpenBmpHeader(headerLen uint16, dataLen uint32) []byte {
	buf := []byte("OBMP")              // magic (4)
	buf = append(buf, OPENBMP_VERSION) // version major (1)
	buf = append(buf, 0x07)            // version minor (1) = 7 for raw
	buf = appendUint16(buf, headerLen) // header length (2)
	buf = appendUint32(buf, dataLen)   // data length (4)
	buf = append(buf, 0x80)            // flags (1): router message
	buf = append(buf, OPENBMP_OBJ_RAW) // object type (1): BMP_RAW
	return buf
}

// makeOpenBmpFullHeader creates a full OpenBMP header with all metadata fields
func makeOpenBmpFullHeader(dataLen uint32, collectorName, routerName string, routerIP netip.Addr, sec, usec uint32) []byte {
	// Calculate header length: 14 (base) + 8 (timestamps) + 16 (coll hash) + 2+len(coll name)
	//   + 16 (router hash) + 16 (router IP) + 2+len(router name) + 4 (row count)
	headerLen := uint16(14 + 8 + 16 + 2 + len(collectorName) + 16 + 16 + 2 + len(routerName) + 4)

	buf := []byte("OBMP")
	buf = append(buf, OPENBMP_VERSION)
	buf = append(buf, 0x07) // minor version

	flags := byte(0x80) // router message
	if routerIP.Is6() {
		flags |= OPENBMP_FLAG_V6
	}

	buf = appendUint16(buf, headerLen)
	buf = appendUint32(buf, dataLen)
	buf = append(buf, flags)
	buf = append(buf, OPENBMP_OBJ_RAW)

	// Timestamps
	buf = appendUint32(buf, sec)
	buf = appendUint32(buf, usec)

	// Collector hash (16 zero bytes)
	buf = append(buf, make([]byte, 16)...)

	// Collector name
	buf = appendUint16(buf, uint16(len(collectorName)))
	buf = append(buf, []byte(collectorName)...)

	// Router hash (16 zero bytes)
	buf = append(buf, make([]byte, 16)...)

	// Router IP (16 bytes)
	if routerIP.Is6() {
		buf = append(buf, routerIP.AsSlice()...)
	} else {
		buf = append(buf, make([]byte, 12)...) // padding for IPv4
		buf = append(buf, routerIP.AsSlice()...)
	}

	// Router name
	buf = appendUint16(buf, uint16(len(routerName)))
	buf = append(buf, []byte(routerName)...)

	// Row count
	buf = appendUint32(buf, 1)

	return buf
}

func TestOpenBmp_FromBytes_Valid(t *testing.T) {
	bmpPayload := makeBmpHeader(HEADLEN, MSG_INITIATION)
	headerLen := uint16(14)
	header := makeOpenBmpHeader(headerLen, uint32(len(bmpPayload)))
	raw := append(header, bmpPayload...)

	o := NewOpenBmp()
	n, err := o.FromBytes(raw)
	require.NoError(t, err)
	require.Equal(t, len(raw), n)
	require.Equal(t, uint8(OPENBMP_VERSION), o.Version)
	require.Equal(t, uint8(0x07), o.Minor)
	require.Equal(t, headerLen, o.HeaderLen)
	require.Equal(t, uint32(len(bmpPayload)), o.DataLen)
	require.True(t, o.IsRouterMessage())
	require.True(t, o.IsBmpRaw())
	require.Equal(t, bmpPayload, o.Data)
}

func TestOpenBmp_FromBytes_FullHeader(t *testing.T) {
	bmpPayload := makeBmpHeader(HEADLEN, MSG_INITIATION)
	routerIP := netip.MustParseAddr("10.0.0.1")
	header := makeOpenBmpFullHeader(uint32(len(bmpPayload)), "collector1", "router1", routerIP, 1700000000, 500000)
	raw := append(header, bmpPayload...)

	o := NewOpenBmp()
	n, err := o.FromBytes(raw)
	require.NoError(t, err)
	require.Equal(t, len(raw), n)
	require.Equal(t, "collector1", o.CollectorName)
	require.Equal(t, "router1", o.RouterName)
	require.Equal(t, routerIP, o.RouterIP)
	require.False(t, o.Time.IsZero())
	require.Equal(t, int64(1700000000), o.Time.Unix())
	require.Equal(t, bmpPayload, o.Data)
}

func TestOpenBmp_FromBytes_IPv6Router(t *testing.T) {
	bmpPayload := makeBmpHeader(HEADLEN, MSG_INITIATION)
	routerIP := netip.MustParseAddr("2001:db8::1")
	header := makeOpenBmpFullHeader(uint32(len(bmpPayload)), "collector1", "router1", routerIP, 1700000000, 0)
	raw := append(header, bmpPayload...)

	o := NewOpenBmp()
	_, err := o.FromBytes(raw)
	require.NoError(t, err)
	require.True(t, o.IsRouterIPv6())
	require.Equal(t, routerIP, o.RouterIP)
}

func TestOpenBmp_FromBytes_InvalidMagic(t *testing.T) {
	raw := []byte("XBMP")              // wrong magic
	raw = append(raw, OPENBMP_VERSION) // version
	raw = append(raw, 0x07)            // minor
	raw = appendUint16(raw, 14)        // header length
	raw = appendUint32(raw, 0)         // data length
	raw = append(raw, 0x80, 12)        // flags, obj type

	o := NewOpenBmp()
	_, err := o.FromBytes(raw)
	require.ErrorIs(t, err, ErrOpenBmpMagic)
}

func TestOpenBmp_FromBytes_InvalidVersion(t *testing.T) {
	raw := []byte("OBMP")       // magic
	raw = append(raw, 0x02)     // wrong version (should be 1)
	raw = append(raw, 0x07)     // minor
	raw = appendUint16(raw, 14) // header length
	raw = appendUint32(raw, 0)  // data length
	raw = append(raw, 0x80, 12) // flags, obj type

	o := NewOpenBmp()
	_, err := o.FromBytes(raw)
	require.ErrorIs(t, err, ErrOpenBmpVersion)
}

func TestOpenBmp_FromBytes_TooShort(t *testing.T) {
	tests := []struct {
		name string
		buf  []byte
	}{
		{"empty", []byte{}},
		{"magic only", []byte("OBMP")},
		{"13 bytes", []byte("OBMP123456789")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := NewOpenBmp()
			_, err := o.FromBytes(tt.buf)
			require.ErrorIs(t, err, ErrShort)
		})
	}
}

func TestOpenBmp_FromBytes_HeaderExceedsBuffer(t *testing.T) {
	raw := makeOpenBmpHeader(100, 0) // header claims 100 bytes but only 14 present
	o := NewOpenBmp()
	_, err := o.FromBytes(raw)
	require.ErrorIs(t, err, ErrLength)
}

func TestOpenBmp_FromBytes_DataExceedsBuffer(t *testing.T) {
	raw := makeOpenBmpHeader(14, 1000) // claims 1000 bytes of data
	o := NewOpenBmp()
	_, err := o.FromBytes(raw)
	require.ErrorIs(t, err, ErrLength)
}

func TestOpenBmp_CopyData(t *testing.T) {
	bmpPayload := makeBmpHeader(HEADLEN, MSG_INITIATION)
	header := makeOpenBmpHeader(14, uint32(len(bmpPayload)))
	raw := append(header, bmpPayload...)

	o := NewOpenBmp()
	_, err := o.FromBytes(raw)
	require.NoError(t, err)

	originalData := o.Data
	o.CopyData()
	require.Equal(t, originalData, o.Data)

	// Modify original buffer - Data should be unaffected
	raw[len(raw)-1] = 0xFF
	require.NotEqual(t, raw[len(raw)-1], o.Data[len(o.Data)-1])
}

func TestOpenBmp_Reset(t *testing.T) {
	bmpPayload := makeBmpHeader(HEADLEN, MSG_INITIATION)
	routerIP := netip.MustParseAddr("10.0.0.1")
	header := makeOpenBmpFullHeader(uint32(len(bmpPayload)), "collector1", "router1", routerIP, 1700000000, 0)
	raw := append(header, bmpPayload...)

	o := NewOpenBmp()
	_, err := o.FromBytes(raw)
	require.NoError(t, err)
	require.NotNil(t, o.Data)
	require.NotEmpty(t, o.CollectorName)

	o.Reset()
	require.Equal(t, uint8(0), o.Version)
	require.Equal(t, uint8(0), o.Minor)
	require.Equal(t, uint16(0), o.HeaderLen)
	require.Equal(t, uint32(0), o.DataLen)
	require.Empty(t, o.CollectorName)
	require.Empty(t, o.RouterName)
	require.False(t, o.RouterIP.IsValid())
	require.True(t, o.Time.IsZero())
	require.Nil(t, o.Data)
}

func TestOpenBmp_Flags(t *testing.T) {
	header := makeOpenBmpHeader(14, 0)

	o := NewOpenBmp()
	_, err := o.FromBytes(header)
	require.NoError(t, err)
	require.True(t, o.IsRouterMessage())
	require.False(t, o.IsRouterIPv6())

	// Test IPv6 flag
	header[12] = OPENBMP_FLAG_RTYPE | OPENBMP_FLAG_V6
	o.Reset()
	_, err = o.FromBytes(header)
	require.NoError(t, err)
	require.True(t, o.IsRouterMessage())
	require.True(t, o.IsRouterIPv6())
}

func TestOpenBmp_FromBytes_InvalidRowCount(t *testing.T) {
	// Create full header with invalid row count (2 instead of 1)
	bmpPayload := makeBmpHeader(HEADLEN, MSG_INITIATION)
	routerIP := netip.MustParseAddr("10.0.0.1")

	// Build header manually to set row count to 2
	headerLen := uint16(14 + 8 + 16 + 2 + len("coll") + 16 + 16 + 2 + len("rtr") + 4)
	buf := []byte("OBMP")
	buf = append(buf, OPENBMP_VERSION, 0x07)
	buf = appendUint16(buf, headerLen)
	buf = appendUint32(buf, uint32(len(bmpPayload)))
	buf = append(buf, 0x80, OPENBMP_OBJ_RAW) // flags, obj type
	buf = appendUint32(buf, 1700000000)      // timestamp sec
	buf = appendUint32(buf, 0)               // timestamp usec
	buf = append(buf, make([]byte, 16)...)   // collector hash
	buf = appendUint16(buf, 4)               // collector name len
	buf = append(buf, []byte("coll")...)     // collector name
	buf = append(buf, make([]byte, 16)...)   // router hash
	buf = append(buf, make([]byte, 12)...)   // router IP padding
	buf = append(buf, routerIP.AsSlice()...) // router IP
	buf = appendUint16(buf, 3)               // router name len
	buf = append(buf, []byte("rtr")...)      // router name
	buf = appendUint32(buf, 2)               // row count = 2 (INVALID!)

	raw := append(buf, bmpPayload...)

	o := NewOpenBmp()
	_, err := o.FromBytes(raw)
	require.ErrorIs(t, err, ErrOpenBmpRowCount)
}

// ============================================================================
// Real-World BMP Message Tests (based on routecore test data)
// These test against actual BMP messages captured from real implementations
// ============================================================================

func TestBmp_RealWorld_RouteMonitoring(t *testing.T) {
	// Real BMP Route Monitoring message from routecore tests
	// Contains one BGP UPDATE with 4 path attributes and 1 IPv4 NLRI
	raw := []byte{
		0x03, 0x00, 0x00, 0x00, 0x67, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x0a, 0xff, 0x00, 0x65,
		0x00, 0x01, 0x00, 0x00, 0x0a, 0x0a, 0x0a, 0x01,
		0x54, 0xa2, 0x0e, 0x0c, 0x00, 0x0e, 0x81, 0x09,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0x00, 0x37, 0x02, 0x00, 0x00, 0x00, 0x1b, 0x40,
		0x01, 0x01, 0x00, 0x40, 0x02, 0x06, 0x02, 0x01,
		0x00, 0x01, 0x00, 0x00, 0x40, 0x03, 0x04, 0x0a,
		0xff, 0x00, 0x65, 0x80, 0x04, 0x04, 0x00, 0x00,
		0x00, 0x01, 0x20, 0x0a, 0x0a, 0x0a, 0x02,
	}

	b := NewBmp()
	n, err := b.FromBytes(raw)
	require.NoError(t, err)
	require.Equal(t, 103, n)
	require.Equal(t, MSG_ROUTE_MONITORING, b.MsgType)
	require.Equal(t, uint32(103), b.MsgLength)

	// Peer header checks
	require.Equal(t, uint8(PEER_TYPE_GLOBAL), b.Peer.Type)
	require.False(t, b.Peer.IsIPv6())
	require.Equal(t, netip.MustParseAddr("10.255.0.101"), b.Peer.Address)
	require.Equal(t, uint32(65536), b.Peer.AS)
	require.Equal(t, uint32(0x0a0a0a01), b.Peer.ID)

	// Verify timestamp (0x54a20e0c = 1419906572, 0x000e8109 = 950537 usec)
	require.Equal(t, int64(1419906572), b.Peer.Time.Unix())

	// BGP data should be present
	require.NotNil(t, b.BgpData)
	require.Equal(t, 55, len(b.BgpData)) // BGP UPDATE message
}

func TestBmp_RealWorld_PeerUpNotification(t *testing.T) {
	// Real BMP PeerUpNotification with two BGP OPEN messages
	raw := []byte{
		0x03, 0x00, 0x00, 0x00, 0xba, 0x03, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x0a, 0xff, 0x00, 0x65,
		0x00, 0x00, 0xfb, 0xf0, 0x0a, 0x0a, 0x0a, 0x01,
		0x54, 0xa2, 0x0e, 0x0b, 0x00, 0x0e, 0x0c, 0x20,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x0a, 0xff, 0x00, 0x53,
		0x90, 0x6e, 0x00, 0xb3, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0x00, 0x3b, 0x01, 0x04,
		0xfb, 0xff, 0x00, 0xb4, 0x0a, 0x0a, 0x0a, 0x67,
		0x1e, 0x02, 0x06, 0x01, 0x04, 0x00, 0x01, 0x00,
		0x01, 0x02, 0x02, 0x80, 0x00, 0x02, 0x02, 0x02,
		0x00, 0x02, 0x06, 0x41, 0x04, 0x00, 0x00, 0xfb,
		0xff, 0x02, 0x04, 0x40, 0x02, 0x00, 0x78, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00,
		0x3b, 0x01, 0x04, 0xfb, 0xf0, 0x00, 0x5a, 0x0a,
		0x0a, 0x0a, 0x01, 0x1e, 0x02, 0x06, 0x01, 0x04,
		0x00, 0x01, 0x00, 0x01, 0x02, 0x02, 0x80, 0x00,
		0x02, 0x02, 0x02, 0x00, 0x02, 0x04, 0x40, 0x02,
		0x00, 0x78, 0x02, 0x06, 0x41, 0x04, 0x00, 0x00,
		0xfb, 0xf0,
	}

	b := NewBmp()
	n, err := b.FromBytes(raw)
	require.NoError(t, err)
	require.Equal(t, 186, n)
	require.Equal(t, MSG_PEER_UP, b.MsgType)
	require.Equal(t, uint32(186), b.MsgLength)

	// Peer header checks
	require.Equal(t, uint8(PEER_TYPE_GLOBAL), b.Peer.Type)
	require.False(t, b.Peer.IsIPv6())
	require.Equal(t, netip.MustParseAddr("10.255.0.101"), b.Peer.Address)
	require.Equal(t, uint32(64496), b.Peer.AS)
	require.Equal(t, uint32(0x0a0a0a01), b.Peer.ID)

	// Verify timestamp (0x54a20e0b = 1419906571, 0x000e0c20 = 920608 usec)
	require.Equal(t, int64(1419906571), b.Peer.Time.Unix())

	// No BGP data for Peer Up (it has embedded OPENs, not exposed via BgpData)
	require.Nil(t, b.BgpData)
}

func TestBmp_RealWorld_PeerDownNotification(t *testing.T) {
	// Real BMP PeerDownNotification with reason=3 (RemoteNotification)
	// Contains a BGP NOTIFICATION (Administrative Shutdown)
	raw := []byte{
		0x03, 0x00, 0x00, 0x00, 0x46, 0x02, 0x00, 0x80,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		0x00, 0x01, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x0a,
		0x62, 0x2d, 0xea, 0x80, 0x00, 0x05, 0x58, 0x22,
		0x03, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0x00, 0x15, 0x03, 0x06, 0x02,
	}

	b := NewBmp()
	n, err := b.FromBytes(raw)
	require.NoError(t, err)
	require.Equal(t, 70, n)
	require.Equal(t, MSG_PEER_DOWN, b.MsgType)

	// Peer header checks - IPv6 peer (V flag 0x80 set, not L flag)
	require.True(t, b.Peer.IsIPv6())
	require.False(t, b.Peer.IsPostPolicy()) // L flag (0x40) not set
	require.Equal(t, netip.MustParseAddr("2001:db8::1"), b.Peer.Address)
	require.Equal(t, uint32(65536), b.Peer.AS)

	// No BGP data exposed for Peer Down
	require.Nil(t, b.BgpData)
}

func TestBmp_RealWorld_StatisticsReport(t *testing.T) {
	// Real BMP statistics report with 13 stats
	raw := []byte{
		0x03, 0x00, 0x00, 0x00, 0xba, 0x01, 0x00, 0x80,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		0x00, 0x01, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x05,
		0x62, 0x50, 0x11, 0x57, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x04,
		0x00, 0x00, 0x00, 0xb0, 0x00, 0x01, 0x00, 0x04,
		0x00, 0x00, 0x04, 0xde, 0x00, 0x02, 0x00, 0x04,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x04,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x04,
		0x00, 0x00, 0x00, 0x0a, 0x00, 0x05, 0x00, 0x04,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x04,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x08,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x25,
		0x00, 0x08, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x1c, 0x00, 0x0e, 0x00, 0x08,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x21, 0x14,
		0x00, 0x0f, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x02, 0x21, 0x14, 0x00, 0x10, 0x00, 0x0b,
		0x00, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x02, 0x21, 0x14, 0x00, 0x11, 0x00, 0x0b, 0x00,
		0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
		0x21, 0x14,
	}

	b := NewBmp()
	n, err := b.FromBytes(raw)
	require.NoError(t, err)
	require.Equal(t, 186, n)
	require.Equal(t, MSG_STATISTICS_REPORT, b.MsgType)

	// Peer header - IPv6 (V flag 0x80 set, not L flag)
	require.True(t, b.Peer.IsIPv6())
	require.False(t, b.Peer.IsPostPolicy()) // L flag (0x40) not set
	require.Equal(t, netip.MustParseAddr("2001:db8::1"), b.Peer.Address)

	// No BGP data for Statistics Report
	require.Nil(t, b.BgpData)
}

func TestBmp_RealWorld_InitiationMessage(t *testing.T) {
	// Real BMP Initiation Message with sysDesc and sysName TLVs
	raw := []byte{
		0x03, 0x00, 0x00, 0x00, 0x6c, 0x04, 0x00, 0x01,
		0x00, 0x5b, 0x43, 0x69, 0x73, 0x63, 0x6f, 0x20,
		0x49, 0x4f, 0x53, 0x20, 0x58, 0x52, 0x20, 0x53,
		0x6f, 0x66, 0x74, 0x77, 0x61, 0x72, 0x65, 0x2c,
		0x20, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e,
		0x20, 0x35, 0x2e, 0x32, 0x2e, 0x32, 0x2e, 0x32,
		0x31, 0x49, 0x5b, 0x44, 0x65, 0x66, 0x61, 0x75,
		0x6c, 0x74, 0x5d, 0x0a, 0x43, 0x6f, 0x70, 0x79,
		0x72, 0x69, 0x67, 0x68, 0x74, 0x20, 0x28, 0x63,
		0x29, 0x20, 0x32, 0x30, 0x31, 0x34, 0x20, 0x62,
		0x79, 0x20, 0x43, 0x69, 0x73, 0x63, 0x6f, 0x20,
		0x53, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x73, 0x2c,
		0x20, 0x49, 0x6e, 0x63, 0x2e, 0x00, 0x02, 0x00,
		0x03, 0x78, 0x72, 0x33,
	}

	b := NewBmp()
	n, err := b.FromBytes(raw)
	require.NoError(t, err)
	require.Equal(t, 108, n)
	require.Equal(t, MSG_INITIATION, b.MsgType)
	require.Equal(t, uint32(108), b.MsgLength)

	// Initiation has no per-peer header
	require.False(t, b.HasPerPeerHeader())
	require.Nil(t, b.BgpData)
}

func TestBmp_RealWorld_TerminationMessage(t *testing.T) {
	// Real BMP Termination message with reason=3 (RedundantConnection)
	raw := []byte{
		0x03, 0x00, 0x00, 0x00, 0x0C, 0x05, 0x00, 0x01,
		0x00, 0x02, 0x00, 0x03,
	}

	b := NewBmp()
	n, err := b.FromBytes(raw)
	require.NoError(t, err)
	require.Equal(t, 12, n)
	require.Equal(t, MSG_TERMINATION, b.MsgType)

	// Termination has no per-peer header
	require.False(t, b.HasPerPeerHeader())
	require.Nil(t, b.BgpData)
}

// ============================================================================
// Peer Header Edge Cases and Flag Tests
// ============================================================================

func TestPeer_RFC8671_AdjRibOutFlag(t *testing.T) {
	// Test the O flag (Adj-RIB-Out) from RFC 8671
	peerIP := netip.MustParseAddr("10.0.0.1")
	flags := uint8(PEER_FLAG_O) // O flag set
	raw := makePeerHeader(PEER_TYPE_GLOBAL, flags, 0, peerIP, 65001, 0x01020304, 1700000000, 0)

	p := &Peer{}
	_, err := p.FromBytes(raw)
	require.NoError(t, err)
	require.True(t, p.IsAdjRibOut())
	require.False(t, p.IsPostPolicy())
	require.False(t, p.IsIPv6())
}

func TestPeer_RFC9069_LocRibType(t *testing.T) {
	// Test peer type 3 = Loc-RIB Instance (RFC 9069)
	peerIP := netip.MustParseAddr("192.168.1.1")
	raw := makePeerHeader(PEER_TYPE_LOC_RIB, 0, 0, peerIP, 65001, 0x01020304, 1700000000, 0)

	p := &Peer{}
	_, err := p.FromBytes(raw)
	require.NoError(t, err)
	require.Equal(t, uint8(PEER_TYPE_LOC_RIB), p.Type)
	require.True(t, p.IsLocRib())
}

func TestPeer_AllFlagsSet(t *testing.T) {
	// All peer flags set: V + L + A + O
	peerIP := netip.MustParseAddr("2001:db8::1")
	flags := uint8(PEER_FLAG_V | PEER_FLAG_L | PEER_FLAG_A | PEER_FLAG_O)
	raw := makePeerHeader(PEER_TYPE_RD, flags, 0x123456789ABCDEF0, peerIP, 65001, 0x01020304, 1700000000, 0)

	p := &Peer{}
	_, err := p.FromBytes(raw)
	require.NoError(t, err)
	require.True(t, p.IsIPv6())
	require.True(t, p.IsPostPolicy())
	require.True(t, p.Is2ByteAS())
	require.True(t, p.IsAdjRibOut())
	require.Equal(t, uint64(0x123456789ABCDEF0), p.RD)
	require.Equal(t, peerIP, p.Address)
}

func TestPeer_TypeConstants(t *testing.T) {
	// Verify peer type constants match IANA registry
	require.Equal(t, uint8(0), PEER_TYPE_GLOBAL)
	require.Equal(t, uint8(1), PEER_TYPE_RD)
	require.Equal(t, uint8(2), PEER_TYPE_LOCAL)
	require.Equal(t, uint8(3), PEER_TYPE_LOC_RIB)
}

func TestPeer_FlagConstants(t *testing.T) {
	// Verify flag constants match RFC 7854/8671
	require.Equal(t, byte(0x80), byte(PEER_FLAG_V))
	require.Equal(t, byte(0x40), byte(PEER_FLAG_L))
	require.Equal(t, byte(0x20), byte(PEER_FLAG_A))
	require.Equal(t, byte(0x10), byte(PEER_FLAG_O))
}
