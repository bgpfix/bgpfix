package rtr

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// --- Wire format helpers ---

// buildHeader builds an 8-byte PDU header.
func buildHeader(version, typ byte, session uint16, length uint32) []byte {
	buf := make([]byte, 8)
	buf[0] = version
	buf[1] = typ
	binary.BigEndian.PutUint16(buf[2:4], session)
	binary.BigEndian.PutUint32(buf[4:8], length)
	return buf
}

// buildCacheResponse builds a Cache Response PDU (8 bytes).
func buildCacheResponse(version byte, sessid uint16) []byte {
	return buildHeader(version, PDUCacheResponse, sessid, 8)
}

// buildIPv4Prefix builds an IPv4 Prefix PDU (20 bytes).
func buildIPv4Prefix(version, flags, pfxlen, maxlen byte, addr [4]byte, asn uint32) []byte {
	buf := make([]byte, 20)
	copy(buf[:8], buildHeader(version, PDUIPv4Prefix, 0, 20))
	buf[8] = flags
	buf[9] = pfxlen
	buf[10] = maxlen
	buf[11] = 0 // reserved
	copy(buf[12:16], addr[:])
	binary.BigEndian.PutUint32(buf[16:20], asn)
	return buf
}

// buildIPv6Prefix builds an IPv6 Prefix PDU (32 bytes).
func buildIPv6Prefix(version, flags, pfxlen, maxlen byte, addr [16]byte, asn uint32) []byte {
	buf := make([]byte, 32)
	copy(buf[:8], buildHeader(version, PDUIPv6Prefix, 0, 32))
	buf[8] = flags
	buf[9] = pfxlen
	buf[10] = maxlen
	buf[11] = 0 // reserved
	copy(buf[12:28], addr[:])
	binary.BigEndian.PutUint32(buf[28:32], asn)
	return buf
}

// buildEndOfData builds an End of Data PDU.
// v0: 12 bytes (no intervals); v1/v2: 24 bytes (with intervals).
func buildEndOfData(version byte, sessid uint16, serial, refresh, retry, expire uint32) []byte {
	if version == VersionV0 {
		buf := make([]byte, 12)
		copy(buf[:8], buildHeader(version, PDUEndOfData, sessid, 12))
		binary.BigEndian.PutUint32(buf[8:12], serial)
		return buf
	}
	buf := make([]byte, 24)
	copy(buf[:8], buildHeader(version, PDUEndOfData, sessid, 24))
	binary.BigEndian.PutUint32(buf[8:12], serial)
	binary.BigEndian.PutUint32(buf[12:16], refresh)
	binary.BigEndian.PutUint32(buf[16:20], retry)
	binary.BigEndian.PutUint32(buf[20:24], expire)
	return buf
}

// buildASPA builds an ASPA PDU (RTR v2).
// For withdrawals, providers must be nil.
func buildASPA(version byte, add bool, cas uint32, providers []uint32) []byte {
	length := uint32(12 + 4*len(providers))
	var flags byte
	if add {
		flags = FlagAnnounce
	}
	// NB: flags is in header byte 2 (high byte of the session/flags field)
	session := uint16(flags) << 8
	buf := make([]byte, length)
	copy(buf[:8], buildHeader(version, PDUAspa, session, length))
	binary.BigEndian.PutUint32(buf[8:12], cas)
	for i, p := range providers {
		binary.BigEndian.PutUint32(buf[12+i*4:], p)
	}
	return buf
}

// buildSerialNotify builds a Serial Notify PDU (12 bytes).
func buildSerialNotify(version byte, sessid uint16, serial uint32) []byte {
	buf := make([]byte, 12)
	copy(buf[:8], buildHeader(version, PDUSerialNotify, sessid, 12))
	binary.BigEndian.PutUint32(buf[8:12], serial)
	return buf
}

// buildCacheReset builds a Cache Reset PDU (8 bytes).
func buildCacheReset(version byte) []byte {
	return buildHeader(version, PDUCacheReset, 0, 8)
}

// buildErrorReport builds an Error Report PDU.
func buildErrorReport(version byte, code uint16, text string) []byte {
	textBytes := []byte(text)
	payloadLen := 4 + 0 + 4 + len(textBytes) // encPDULen(4) + encPDU(0) + textLen(4) + text
	total := uint32(8 + payloadLen)
	buf := make([]byte, total)
	copy(buf[:8], buildHeader(version, PDUErrorReport, code, total))
	// encPDULen = 0 (no encapsulated PDU)
	binary.BigEndian.PutUint32(buf[8:12], 0)
	// textLen
	binary.BigEndian.PutUint32(buf[12:16], uint32(len(textBytes)))
	copy(buf[16:], textBytes)
	return buf
}

// --- Wire format encoding tests ---

func TestResetQuery_Wire(t *testing.T) {
	tests := []struct {
		version byte
		want    []byte
	}{
		{VersionV0, []byte{0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08}},
		{VersionV1, []byte{0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08}},
		{VersionV2, []byte{0x02, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08}},
	}
	for _, tc := range tests {
		var buf bytes.Buffer
		require.NoError(t, writeResetQuery(&buf, tc.version))
		require.Equal(t, tc.want, buf.Bytes())
	}
}

func TestSerialQuery_Wire(t *testing.T) {
	tests := []struct {
		version byte
		sessid  uint16
		serial  uint32
		want    []byte
	}{
		{
			VersionV1, 0x0042, 1,
			[]byte{
				0x01, 0x01, // version=1, type=SerialQuery
				0x00, 0x42, // sessid=0x0042
				0x00, 0x00, 0x00, 0x0C, // length=12
				0x00, 0x00, 0x00, 0x01, // serial=1
			},
		},
		{
			VersionV2, 0xFFFF, 0xDEADBEEF,
			[]byte{
				0x02, 0x01,
				0xFF, 0xFF,
				0x00, 0x00, 0x00, 0x0C,
				0xDE, 0xAD, 0xBE, 0xEF,
			},
		},
	}
	for _, tc := range tests {
		var buf bytes.Buffer
		require.NoError(t, writeSerialQuery(&buf, tc.version, tc.sessid, tc.serial))
		require.Equal(t, tc.want, buf.Bytes())
	}
}

// --- PDU parsing tests ---

// parsePDU is a test helper that reads one PDU from wire bytes and returns its header and payload.
func parsePDU(t *testing.T, wire []byte) (pduHeader, []byte) {
	t.Helper()
	r := bytes.NewReader(wire)
	h, err := readHeader(r)
	require.NoError(t, err)
	payload, err := readPayload(r, h)
	require.NoError(t, err)
	return h, payload
}

func TestIPv4Prefix_Announce(t *testing.T) {
	// 192.0.2.0/24, maxlen=24, ASN=65001
	wire := buildIPv4Prefix(VersionV1, FlagAnnounce, 24, 24, [4]byte{192, 0, 2, 0}, 65001)
	require.Equal(t, 20, len(wire))

	// verify known bytes
	require.Equal(t, byte(VersionV1), wire[0])
	require.Equal(t, byte(PDUIPv4Prefix), wire[1])
	require.Equal(t, byte(0x14), wire[7]) // length low byte = 20

	h, payload := parsePDU(t, wire)
	require.Equal(t, byte(PDUIPv4Prefix), h.Type)
	require.Equal(t, uint32(20), h.Length)

	var gotAdd bool
	var gotPrefix netip.Prefix
	var gotMaxLen uint8
	var gotASN uint32
	c := NewClient(&Options{
		OnROA: func(add bool, prefix netip.Prefix, maxLen uint8, asn uint32) {
			gotAdd, gotPrefix, gotMaxLen, gotASN = add, prefix, maxLen, asn
		},
	})
	require.NoError(t, c.dispatch(nil, h, payload, nil))
	require.True(t, gotAdd)
	require.Equal(t, netip.MustParsePrefix("192.0.2.0/24"), gotPrefix)
	require.Equal(t, uint8(24), gotMaxLen)
	require.Equal(t, uint32(65001), gotASN)
}

func TestIPv4Prefix_Withdraw(t *testing.T) {
	wire := buildIPv4Prefix(VersionV1, FlagWithdraw, 24, 24, [4]byte{192, 0, 2, 0}, 65001)
	h, payload := parsePDU(t, wire)
	var gotAdd = true
	c := NewClient(&Options{
		OnROA: func(add bool, _ netip.Prefix, _ uint8, _ uint32) { gotAdd = add },
	})
	require.NoError(t, c.dispatch(nil, h, payload, nil))
	require.False(t, gotAdd)
}

func TestIPv4Prefix_MaxLenVariant(t *testing.T) {
	// 10.0.0.0/8 with maxlen=24 (more specific allowed)
	wire := buildIPv4Prefix(VersionV1, FlagAnnounce, 8, 24, [4]byte{10, 0, 0, 0}, 65100)
	h, payload := parsePDU(t, wire)
	var gotPrefix netip.Prefix
	var gotMaxLen uint8
	c := NewClient(&Options{
		OnROA: func(_ bool, prefix netip.Prefix, maxLen uint8, _ uint32) {
			gotPrefix, gotMaxLen = prefix, maxLen
		},
	})
	require.NoError(t, c.dispatch(nil, h, payload, nil))
	require.Equal(t, netip.MustParsePrefix("10.0.0.0/8"), gotPrefix)
	require.Equal(t, uint8(24), gotMaxLen)
}

func TestIPv6Prefix_Announce(t *testing.T) {
	// 2001:db8::/32, maxlen=48, ASN=65001
	var addr [16]byte
	addr[0], addr[1] = 0x20, 0x01
	addr[2], addr[3] = 0x0d, 0xb8
	wire := buildIPv6Prefix(VersionV1, FlagAnnounce, 32, 48, addr, 65001)
	require.Equal(t, 32, len(wire))

	h, payload := parsePDU(t, wire)
	require.Equal(t, byte(PDUIPv6Prefix), h.Type)

	var gotPrefix netip.Prefix
	var gotMaxLen uint8
	c := NewClient(&Options{
		OnROA: func(_ bool, prefix netip.Prefix, maxLen uint8, _ uint32) {
			gotPrefix, gotMaxLen = prefix, maxLen
		},
	})
	require.NoError(t, c.dispatch(nil, h, payload, nil))
	require.Equal(t, netip.MustParsePrefix("2001:db8::/32"), gotPrefix)
	require.Equal(t, uint8(48), gotMaxLen)
}

func TestIPv6Prefix_Withdraw(t *testing.T) {
	var addr [16]byte
	addr[0], addr[1] = 0x20, 0x01
	wire := buildIPv6Prefix(VersionV1, FlagWithdraw, 32, 48, addr, 65001)
	h, payload := parsePDU(t, wire)
	var gotAdd = true
	c := NewClient(&Options{
		OnROA: func(add bool, _ netip.Prefix, _ uint8, _ uint32) { gotAdd = add },
	})
	require.NoError(t, c.dispatch(nil, h, payload, nil))
	require.False(t, gotAdd)
}

func TestEndOfData_V0(t *testing.T) {
	// v0: 12 bytes, no intervals
	wire := buildEndOfData(VersionV0, 0x0042, 100, 0, 0, 0)
	require.Equal(t, 12, len(wire))

	h, payload := parsePDU(t, wire)
	require.Equal(t, byte(PDUEndOfData), h.Type)
	require.Equal(t, uint32(12), h.Length)
	require.Equal(t, uint16(0x0042), h.Session)

	var gotSessid uint16
	var gotSerial uint32
	c := NewClient(&Options{
		OnEndOfData: func(sessid uint16, serial uint32) {
			gotSessid, gotSerial = sessid, serial
		},
	})
	require.NoError(t, c.dispatch(nil, h, payload, nil))
	require.Equal(t, uint16(0x0042), gotSessid)
	require.Equal(t, uint32(100), gotSerial)
	require.True(t, c.hasSerial)
}

func TestEndOfData_V1(t *testing.T) {
	// v1/v2: 24 bytes with refresh=3600, retry=600, expire=7200
	wire := buildEndOfData(VersionV1, 0x0001, 42, 3600, 600, 7200)
	require.Equal(t, 24, len(wire))

	h, payload := parsePDU(t, wire)
	require.Equal(t, byte(PDUEndOfData), h.Type)
	require.Equal(t, uint32(24), h.Length)

	var gotSerial uint32
	c := NewClient(&Options{
		OnEndOfData: func(_ uint16, serial uint32) { gotSerial = serial },
	})
	require.NoError(t, c.dispatch(nil, h, payload, nil))
	require.Equal(t, uint32(42), gotSerial)
}

func TestASPA_Announce(t *testing.T) {
	// CAS=65001, providers=[65002, 65003]
	wire := buildASPA(VersionV2, true, 65001, []uint32{65002, 65003})
	require.Equal(t, 20, len(wire)) // 12 + 4*2

	// verify flags byte is at position 2
	require.Equal(t, byte(FlagAnnounce), wire[2])
	require.Equal(t, byte(0), wire[3]) // reserved

	h, payload := parsePDU(t, wire)
	require.Equal(t, byte(PDUAspa), h.Type)
	require.Equal(t, uint16(0x0100), h.Session) // flags=1 in high byte

	var gotAdd bool
	var gotCAS uint32
	var gotProviders []uint32
	c := NewClient(&Options{
		OnASPA: func(add bool, cas uint32, providers []uint32) {
			gotAdd, gotCAS, gotProviders = add, cas, providers
		},
	})
	require.NoError(t, c.dispatch(nil, h, payload, nil))
	require.True(t, gotAdd)
	require.Equal(t, uint32(65001), gotCAS)
	require.Equal(t, []uint32{65002, 65003}, gotProviders)
}

func TestASPA_Withdraw(t *testing.T) {
	// withdrawal: no providers, length=12
	wire := buildASPA(VersionV2, false, 65001, nil)
	require.Equal(t, 12, len(wire))
	require.Equal(t, byte(FlagWithdraw), wire[2]) // flags=0

	h, payload := parsePDU(t, wire)
	var gotAdd = true
	var gotProviders = []uint32{99} // should be cleared to nil
	c := NewClient(&Options{
		OnASPA: func(add bool, _ uint32, providers []uint32) {
			gotAdd, gotProviders = add, providers
		},
	})
	require.NoError(t, c.dispatch(nil, h, payload, nil))
	require.False(t, gotAdd)
	require.Nil(t, gotProviders)
}

func TestASPA_IgnoredOnV1(t *testing.T) {
	// ASPA PDU from a v1 server should be silently ignored
	wire := buildASPA(VersionV1, true, 65001, []uint32{65002})
	h, payload := parsePDU(t, wire)
	h.Version = VersionV1 // override version in header to v1

	called := false
	c := NewClient(&Options{
		OnASPA: func(_ bool, _ uint32, _ []uint32) { called = true },
	})
	require.NoError(t, c.dispatch(nil, h, payload, nil))
	require.False(t, called)
}

func TestASPA_NoProviders_AnnounceIsEmpty(t *testing.T) {
	// Per spec, announcement should have ≥1 provider, but we accept empty gracefully
	wire := buildASPA(VersionV2, true, 65001, []uint32{})
	h, payload := parsePDU(t, wire)

	var gotProviders []uint32
	c := NewClient(&Options{
		OnASPA: func(_ bool, _ uint32, providers []uint32) { gotProviders = providers },
	})
	require.NoError(t, c.dispatch(nil, h, payload, nil))
	require.Empty(t, gotProviders)
}

func TestCacheResponse(t *testing.T) {
	wire := buildCacheResponse(VersionV1, 0x1234)
	h, payload := parsePDU(t, wire)
	require.Equal(t, byte(PDUCacheResponse), h.Type)
	require.Nil(t, payload)

	c := NewClient(nil)
	ver := VersionV1
	require.NoError(t, c.dispatch(nil, h, payload, &ver))
	c.mu.Lock()
	require.Equal(t, byte(VersionV1), c.version)
	require.Equal(t, uint16(0x1234), c.sessid)
	c.mu.Unlock()
}

func TestCacheReset_SendsResetQuery(t *testing.T) {
	wire := buildCacheReset(VersionV1)
	h, payload := parsePDU(t, wire)

	resetCalled := false
	var sendBuf bytes.Buffer
	c := NewClient(&Options{
		OnCacheReset: func() { resetCalled = true },
	})
	ver := VersionV1
	require.NoError(t, c.dispatch(&sendBuf, h, payload, &ver))
	require.True(t, resetCalled)
	// verify a Reset Query was sent
	require.Equal(t, []byte{0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08}, sendBuf.Bytes())
}

func TestSerialNotify_SendsSerialQuery(t *testing.T) {
	// Set up client with a known serial
	c := NewClient(nil)
	c.mu.Lock()
	c.hasSerial = true
	c.sessid = 0x0042
	c.serial = 99
	c.version = VersionV1
	c.mu.Unlock()

	wire := buildSerialNotify(VersionV1, 0x0042, 100) // server has serial 100, we have 99
	h, payload := parsePDU(t, wire)

	var sendBuf bytes.Buffer
	ver := VersionV1
	require.NoError(t, c.dispatch(&sendBuf, h, payload, &ver))

	// verify a Serial Query was sent with our current serial (99)
	want := []byte{
		0x01, 0x01, // version=1, type=SerialQuery
		0x00, 0x42, // sessid=0x0042
		0x00, 0x00, 0x00, 0x0C, // length=12
		0x00, 0x00, 0x00, 0x63, // serial=99
	}
	require.Equal(t, want, sendBuf.Bytes())
}

func TestSerialNotify_SameSerial_NoQuery(t *testing.T) {
	// If serial matches, no query should be sent
	c := NewClient(nil)
	c.mu.Lock()
	c.hasSerial = true
	c.serial = 100
	c.mu.Unlock()

	wire := buildSerialNotify(VersionV1, 0, 100) // same serial
	h, payload := parsePDU(t, wire)

	var sendBuf bytes.Buffer
	ver := VersionV1
	require.NoError(t, c.dispatch(&sendBuf, h, payload, &ver))
	require.Zero(t, sendBuf.Len())
}

func TestSerialNotify_NoSerial_NoQuery(t *testing.T) {
	// If we haven't received a full cache yet, don't send serial query
	c := NewClient(nil)
	wire := buildSerialNotify(VersionV1, 0, 100)
	h, payload := parsePDU(t, wire)

	var sendBuf bytes.Buffer
	ver := VersionV1
	require.NoError(t, c.dispatch(&sendBuf, h, payload, &ver))
	require.Zero(t, sendBuf.Len())
}

func TestErrorReport_Parse(t *testing.T) {
	wire := buildErrorReport(VersionV1, ErrNoData, "no data available")
	h, payload := parsePDU(t, wire)
	require.Equal(t, byte(PDUErrorReport), h.Type)
	require.Equal(t, uint16(ErrNoData), h.Session)

	var gotCode uint16
	var gotText string
	c := NewClient(&Options{
		OnError: func(code uint16, text string) { gotCode, gotText = code, text },
	})
	ver := VersionV1
	require.NoError(t, c.dispatch(nil, h, payload, &ver))
	require.Equal(t, uint16(ErrNoData), gotCode)
	require.Equal(t, "no data available", gotText)
}

func TestErrorReport_EmptyText(t *testing.T) {
	wire := buildErrorReport(VersionV1, ErrInternal, "")
	h, payload := parsePDU(t, wire)
	var gotText = "unchanged"
	c := NewClient(&Options{
		OnError: func(_ uint16, text string) { gotText = text },
	})
	ver := VersionV1
	require.NoError(t, c.dispatch(nil, h, payload, &ver))
	require.Equal(t, "", gotText)
}

func TestVersionDowngrade_V2ToV1(t *testing.T) {
	wire := buildErrorReport(VersionV1, ErrUnsupVersion, "unsupported")
	h, payload := parsePDU(t, wire)

	var sendBuf bytes.Buffer
	c := NewClient(nil)
	ver := VersionV2 // we're trying v2, server says no
	require.NoError(t, c.dispatch(&sendBuf, h, payload, &ver))

	// version should have been decremented to v1
	require.Equal(t, VersionV1, ver)
	// a Reset Query with v1 should have been sent
	require.Equal(t, []byte{0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08}, sendBuf.Bytes())
}

func TestVersionDowngrade_V1ToV0(t *testing.T) {
	wire := buildErrorReport(VersionV1, ErrUnsupVersion, "")
	h, payload := parsePDU(t, wire)

	var sendBuf bytes.Buffer
	c := NewClient(nil)
	ver := VersionV1
	require.NoError(t, c.dispatch(&sendBuf, h, payload, &ver))

	require.Equal(t, VersionV0, ver)
	require.Equal(t, []byte{0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08}, sendBuf.Bytes())
}

func TestVersionDowngrade_V0_NoFurtherDowngrade(t *testing.T) {
	wire := buildErrorReport(VersionV0, ErrUnsupVersion, "")
	h, payload := parsePDU(t, wire)

	var sendBuf bytes.Buffer
	c := NewClient(nil)
	ver := VersionV0
	require.NoError(t, c.dispatch(&sendBuf, h, payload, &ver))
	// still v0, no query sent (can't go lower)
	require.Equal(t, VersionV0, ver)
	require.Zero(t, sendBuf.Len())
}

func TestUnknownPDUType_Ignored(t *testing.T) {
	// Unknown PDU type should not cause panic or error
	wire := buildHeader(VersionV1, 0xFF, 0, 8) // type 0xFF unknown
	h, payload := parsePDU(t, wire)
	c := NewClient(nil)
	require.NoError(t, c.dispatch(nil, h, payload, nil))
}

func TestRouterKey_Ignored(t *testing.T) {
	// Router Key PDU should be silently ignored
	// Minimal Router Key: header(8) + flags(1) + reserved(1) + SKI(20) + ASN(4) + key(varies)
	keyLen := uint32(8 + 1 + 1 + 20 + 4 + 10)
	wire := buildHeader(VersionV1, PDURouterKey, 0, keyLen)
	// pad to length
	wire = append(wire, make([]byte, keyLen-8)...)
	h, payload := parsePDU(t, wire)
	c := NewClient(nil)
	require.NoError(t, c.dispatch(nil, h, payload, nil))
}

func TestParseErrorText(t *testing.T) {
	tests := []struct {
		name    string
		payload []byte
		want    string
	}{
		{"empty payload", []byte{}, ""},
		{"too short", []byte{0, 0, 0}, ""},
		{"no encPDU, no text", []byte{0, 0, 0, 0, 0, 0, 0, 0}, ""},
		{
			"no encPDU, with text",
			func() []byte {
				text := []byte("test error")
				buf := make([]byte, 4+4+len(text))
				binary.BigEndian.PutUint32(buf[4:8], uint32(len(text)))
				copy(buf[8:], text)
				return buf
			}(),
			"test error",
		},
		{
			"with encPDU, with text",
			func() []byte {
				encPDU := []byte{0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08}
				text := []byte("corrupt")
				buf := make([]byte, 4+len(encPDU)+4+len(text))
				binary.BigEndian.PutUint32(buf[0:4], uint32(len(encPDU)))
				copy(buf[4:], encPDU)
				binary.BigEndian.PutUint32(buf[4+len(encPDU):], uint32(len(text)))
				copy(buf[4+len(encPDU)+4:], text)
				return buf
			}(),
			"corrupt",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, parseErrorText(tc.payload))
		})
	}
}

// --- Integration tests using net.Pipe ---

// serverWrite is a test helper that writes PDU bytes to the server side of a pipe.
func serverWrite(t *testing.T, server net.Conn, pdus ...[]byte) {
	t.Helper()
	for _, pdu := range pdus {
		_, err := server.Write(pdu)
		require.NoError(t, err)
	}
}

// clientReadQuery is a test helper that reads a query PDU from the server side
// (i.e., what the client sent to the server).
func clientReadQuery(t *testing.T, server net.Conn, maxLen int) []byte {
	t.Helper()
	buf := make([]byte, maxLen)
	deadline := time.Now().Add(5 * time.Second)
	if dl, ok := t.Deadline(); ok {
		deadline = dl.Add(-time.Second) // leave 1s margin before test timeout
	}
	server.SetReadDeadline(deadline)
	n, err := io.ReadAtLeast(server, buf, 8)
	require.NoError(t, err)
	return buf[:n]
}

func TestSession_BasicROVFlow(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	var mu sync.Mutex
	var roas []struct {
		add    bool
		prefix netip.Prefix
		maxLen uint8
		asn    uint32
	}
	var endOfDataCalled bool
	eodSignal, eodCh := waitChan(1)

	c := NewClient(&Options{
		Version: VersionAuto,
		OnROA: func(add bool, prefix netip.Prefix, maxLen uint8, asn uint32) {
			mu.Lock()
			roas = append(roas, struct {
				add    bool
				prefix netip.Prefix
				maxLen uint8
				asn    uint32
			}{add, prefix, maxLen, asn})
			mu.Unlock()
		},
		OnEndOfData: func(_ uint16, _ uint32) {
			mu.Lock()
			endOfDataCalled = true
			mu.Unlock()
			eodSignal()
		},
	})

	ctx, cancel := ctxWithTimeout(t)
	defer cancel()

	// run client in background
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx, client) }()

	// read the initial Reset Query from client
	q := clientReadQuery(t, server, 8)
	require.Equal(t, byte(PDUResetQuery), q[1])
	require.Equal(t, byte(VersionV2), q[0]) // auto starts with v2

	// send: CacheResponse + 2 IPv4 + 1 IPv6 + EndOfData
	serverWrite(t, server,
		buildCacheResponse(VersionV1, 0x0001),
		buildIPv4Prefix(VersionV1, FlagAnnounce, 24, 24, [4]byte{192, 0, 2, 0}, 65001),
		buildIPv4Prefix(VersionV1, FlagAnnounce, 16, 24, [4]byte{10, 0, 0, 0}, 65002),
		buildIPv6Prefix(VersionV1, FlagAnnounce, 48, 48,
			func() [16]byte { var a [16]byte; a[0] = 0x20; a[1] = 0x01; return a }(),
			65003),
		buildEndOfData(VersionV1, 0x0001, 1, 3600, 600, 7200),
	)

	// wait for EndOfData callback
	<-eodCh
	cancel()
	<-done

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, roas, 3)
	require.True(t, endOfDataCalled)
	require.Equal(t, uint32(65001), roas[0].asn)
	require.Equal(t, uint32(65002), roas[1].asn)
	require.Equal(t, uint32(65003), roas[2].asn)
}

func TestSession_ASPAFlow(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	var mu sync.Mutex
	type aspaEntry struct {
		add       bool
		cas       uint32
		providers []uint32
	}
	var aspas []aspaEntry

	eodSignal, eodCh := waitChan(1)
	c := NewClient(&Options{
		Version: VersionAuto,
		OnASPA: func(add bool, cas uint32, providers []uint32) {
			mu.Lock()
			aspas = append(aspas, aspaEntry{add, cas, append([]uint32(nil), providers...)})
			mu.Unlock()
		},
		OnEndOfData: func(_ uint16, _ uint32) { eodSignal() },
	})

	ctx, cancel := ctxWithTimeout(t)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- c.Run(ctx, client) }()

	// read Reset Query
	q := clientReadQuery(t, server, 8)
	require.Equal(t, byte(PDUResetQuery), q[1])

	// send v2 session with ASPA records
	serverWrite(t, server,
		buildCacheResponse(VersionV2, 0x0001),
		buildASPA(VersionV2, true, 65001, []uint32{65100, 65200}),
		buildASPA(VersionV2, true, 65002, []uint32{65100}),
		buildEndOfData(VersionV2, 0x0001, 1, 3600, 600, 7200),
	)

	<-eodCh
	cancel()
	<-done

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, aspas, 2)
	require.Equal(t, uint32(65001), aspas[0].cas)
	require.Equal(t, []uint32{65100, 65200}, aspas[0].providers)
	require.Equal(t, uint32(65002), aspas[1].cas)
	require.Equal(t, []uint32{65100}, aspas[1].providers)
}

func TestSession_ASPAWithdraw(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	var mu sync.Mutex
	var events []bool // add/withdraw events

	eodSignal, eodCh := waitChan(2)
	c := NewClient(&Options{
		Version: VersionAuto,
		OnASPA: func(add bool, _ uint32, _ []uint32) {
			mu.Lock()
			events = append(events, add)
			mu.Unlock()
		},
		OnEndOfData: func(_ uint16, _ uint32) { eodSignal() },
	})

	ctx, cancel := ctxWithTimeout(t)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- c.Run(ctx, client) }()
	clientReadQuery(t, server, 8) // consume Reset Query

	serverWrite(t, server,
		buildCacheResponse(VersionV2, 0x0001),
		buildASPA(VersionV2, true, 65001, []uint32{65100}),  // announce
		buildEndOfData(VersionV2, 0x0001, 1, 3600, 600, 7200),
		buildSerialNotify(VersionV2, 0x0001, 2),
	)
	// consume Serial Query
	clientReadQuery(t, server, 12)

	serverWrite(t, server,
		buildCacheResponse(VersionV2, 0x0001),
		buildASPA(VersionV2, false, 65001, nil), // withdraw
		buildEndOfData(VersionV2, 0x0001, 2, 3600, 600, 7200),
	)

	<-eodCh
	cancel()
	<-done

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, events, 2)
	require.True(t, events[0])  // announce
	require.False(t, events[1]) // withdraw
}

func TestSession_VersionNegotiation_V2ToV1(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	var mu sync.Mutex
	var roaCount int

	eodSignal, eodCh := waitChan(1)
	c := NewClient(&Options{
		Version: VersionAuto,
		OnROA: func(_ bool, _ netip.Prefix, _ uint8, _ uint32) {
			mu.Lock()
			roaCount++
			mu.Unlock()
		},
		OnEndOfData: func(_ uint16, _ uint32) { eodSignal() },
	})

	ctx, cancel := ctxWithTimeout(t)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- c.Run(ctx, client) }()

	// first query: client sends v2 Reset Query
	q := clientReadQuery(t, server, 8)
	require.Equal(t, byte(VersionV2), q[0])
	require.Equal(t, byte(PDUResetQuery), q[1])

	// server rejects v2
	serverWrite(t, server, buildErrorReport(VersionV1, ErrUnsupVersion, "use v1"))

	// client should retry with v1 Reset Query
	q = clientReadQuery(t, server, 8)
	require.Equal(t, byte(VersionV1), q[0])
	require.Equal(t, byte(PDUResetQuery), q[1])

	// now send v1 data
	serverWrite(t, server,
		buildCacheResponse(VersionV1, 0x0002),
		buildIPv4Prefix(VersionV1, FlagAnnounce, 24, 24, [4]byte{1, 2, 3, 0}, 65001),
		buildEndOfData(VersionV1, 0x0002, 5, 3600, 600, 7200),
	)

	<-eodCh
	cancel()
	<-done

	mu.Lock()
	defer mu.Unlock()
	require.Equal(t, 1, roaCount)
	require.Equal(t, VersionV1, c.Version())
}

func TestSession_CacheReset(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	resetCount := 0
	resetSignal, resetCh := waitChan(1)
	c := NewClient(&Options{
		Version:      VersionAuto,
		OnCacheReset: func() { resetCount++; resetSignal() },
	})

	ctx, cancel := ctxWithTimeout(t)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- c.Run(ctx, client) }()

	// read initial Reset Query
	clientReadQuery(t, server, 8)

	// send partial data then cache reset
	serverWrite(t, server,
		buildCacheResponse(VersionV1, 0x0001),
		buildIPv4Prefix(VersionV1, FlagAnnounce, 24, 24, [4]byte{1, 0, 0, 0}, 65001),
		buildCacheReset(VersionV1),
	)

	// wait for cache reset callback, then read the new Reset Query
	<-resetCh
	q := clientReadQuery(t, server, 8)
	require.Equal(t, byte(PDUResetQuery), q[1])

	cancel()
	<-done

	require.Equal(t, 1, resetCount)
}

func TestSession_SerialQuery_Flow(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	var mu sync.Mutex
	var roas []uint32 // ASNs of received ROAs

	eodSignal1, eodCh1 := waitChan(1)
	eodSignal2, eodCh2 := waitChan(2)
	c := NewClient(&Options{
		Version: VersionAuto,
		OnROA: func(add bool, _ netip.Prefix, _ uint8, asn uint32) {
			if add {
				mu.Lock()
				roas = append(roas, asn)
				mu.Unlock()
			}
		},
		OnEndOfData: func(_ uint16, _ uint32) {
			eodSignal1()
			eodSignal2()
		},
	})

	ctx, cancel := ctxWithTimeout(t)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- c.Run(ctx, client) }()

	// initial full sync
	clientReadQuery(t, server, 8)
	serverWrite(t, server,
		buildCacheResponse(VersionV1, 0x0001),
		buildIPv4Prefix(VersionV1, FlagAnnounce, 24, 24, [4]byte{1, 0, 0, 0}, 65001),
		buildEndOfData(VersionV1, 0x0001, 10, 3600, 600, 7200),
	)
	<-eodCh1

	// trigger incremental update via SerialNotify
	serverWrite(t, server, buildSerialNotify(VersionV1, 0x0001, 11))

	// client should send Serial Query with serial=10
	q := clientReadQuery(t, server, 12)
	require.Equal(t, byte(PDUSerialQuery), q[1])
	require.Equal(t, uint32(10), binary.BigEndian.Uint32(q[8:12]))

	// send incremental update
	serverWrite(t, server,
		buildCacheResponse(VersionV1, 0x0001),
		buildIPv4Prefix(VersionV1, FlagAnnounce, 24, 24, [4]byte{2, 0, 0, 0}, 65002),
		buildEndOfData(VersionV1, 0x0001, 11, 3600, 600, 7200),
	)

	<-eodCh2
	cancel()
	<-done

	mu.Lock()
	defer mu.Unlock()
	require.Equal(t, []uint32{65001, 65002}, roas)
}

func TestSession_ContextCancel(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()

	c := NewClient(nil)
	ctx, cancel := ctxWithTimeout(t)

	done := make(chan error, 1)
	go func() { done <- c.Run(ctx, client) }()

	// read initial Reset Query to ensure client started
	clientReadQuery(t, server, 8)

	// cancel context
	cancel()

	select {
	case err := <-done:
		require.Error(t, err) // should return context error or io error
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Run did not return within 500ms after context cancel")
	}
}

func TestSession_ConnDrop(t *testing.T) {
	client, server := net.Pipe()

	c := NewClient(nil)
	ctx, cancel := ctxWithTimeout(t)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- c.Run(ctx, client) }()

	// read initial Reset Query
	clientReadQuery(t, server, 8)

	// drop the server side
	server.Close()

	select {
	case err := <-done:
		require.Error(t, err) // should return io.EOF or similar
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Run did not return within 500ms after conn drop")
	}
}

func TestSendSerial_NotConnected(t *testing.T) {
	c := NewClient(nil)
	// not connected, not hasSerial → should return false gracefully
	require.False(t, c.SendSerial())
}

func TestSendSerial_NoCache(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()

	c := NewClient(nil)
	ctx, cancel := ctxWithTimeout(t)
	defer cancel()

	go c.Run(ctx, client)
	clientReadQuery(t, server, 8) // consume Reset Query

	// hasSerial is false → SendSerial returns false
	require.False(t, c.SendSerial())
}

// --- Malformed payload tests ---

func TestIPv4Prefix_TruncatedPayload(t *testing.T) {
	h := pduHeader{Type: PDUIPv4Prefix, Version: VersionV1, Length: 14}
	payload := make([]byte, 6) // need 12
	c := NewClient(nil)
	require.Error(t, c.dispatch(nil, h, payload, nil))
}

func TestIPv6Prefix_TruncatedPayload(t *testing.T) {
	h := pduHeader{Type: PDUIPv6Prefix, Version: VersionV1, Length: 18}
	payload := make([]byte, 10) // need 24
	c := NewClient(nil)
	require.Error(t, c.dispatch(nil, h, payload, nil))
}

func TestASPA_TruncatedPayload(t *testing.T) {
	h := pduHeader{Type: PDUAspa, Version: VersionV2, Session: 0x0100, Length: 10}
	payload := make([]byte, 2) // need >= 4
	c := NewClient(nil)
	require.Error(t, c.dispatch(nil, h, payload, nil))
}

func TestEndOfData_TruncatedPayload(t *testing.T) {
	h := pduHeader{Type: PDUEndOfData, Version: VersionV1, Session: 1, Length: 10}
	payload := make([]byte, 2) // need >= 4
	c := NewClient(nil)
	require.Error(t, c.dispatch(nil, h, payload, nil))
}

func TestSerialNotify_TruncatedPayload(t *testing.T) {
	h := pduHeader{Type: PDUSerialNotify, Version: VersionV1, Session: 1, Length: 10}
	payload := make([]byte, 2) // need >= 4
	c := NewClient(nil)
	require.Error(t, c.dispatch(nil, h, payload, nil))
}

func TestASPA_NonAlignedPayload(t *testing.T) {
	// 4 (CAS) + 5 bytes = not 4-byte aligned after CAS
	h := pduHeader{Type: PDUAspa, Version: VersionV2, Session: 0x0100, Length: 17}
	payload := make([]byte, 9)
	binary.BigEndian.PutUint32(payload[0:4], 65001)
	c := NewClient(nil)
	require.Error(t, c.dispatch(nil, h, payload, nil))
}

// --- Oversized PDU test ---

func TestReadPayload_Oversized(t *testing.T) {
	h := pduHeader{Type: PDUIPv4Prefix, Version: VersionV1, Length: 0xFFFFFFFF}
	_, err := readPayload(bytes.NewReader(nil), h)
	require.Error(t, err)
	require.Contains(t, err.Error(), "exceeds max")
}

func TestReadPayload_HeaderOnly(t *testing.T) {
	h := pduHeader{Type: PDUResetQuery, Version: VersionV1, Length: 8}
	payload, err := readPayload(bytes.NewReader(nil), h)
	require.NoError(t, err)
	require.Nil(t, payload)
}

func TestReadPayload_TooSmall(t *testing.T) {
	h := pduHeader{Type: PDUIPv4Prefix, Version: VersionV1, Length: 5}
	_, err := readPayload(bytes.NewReader(nil), h)
	require.Error(t, err)
	require.Contains(t, err.Error(), "< 8")
}

// --- Session ID change in SerialNotify ---

func TestSerialNotify_SessionChange_SendsResetQuery(t *testing.T) {
	c := NewClient(nil)
	c.mu.Lock()
	c.hasSerial = true
	c.sessid = 0x0001
	c.serial = 99
	c.version = VersionV1
	c.mu.Unlock()

	// SerialNotify with a different session ID
	wire := buildSerialNotify(VersionV1, 0x0002, 100)
	h, payload := parsePDU(t, wire)

	var sendBuf bytes.Buffer
	ver := VersionV1
	require.NoError(t, c.dispatch(&sendBuf, h, payload, &ver))

	// should send Reset Query, not Serial Query
	require.Equal(t, 8, sendBuf.Len(), "expected 8-byte Reset Query, got %d bytes", sendBuf.Len())
	require.Equal(t, byte(PDUResetQuery), sendBuf.Bytes()[1])
}

// --- Goroutine leak test ---

func TestRun_NoGoroutineLeak_OnIOError(t *testing.T) {
	client, server := net.Pipe()

	c := NewClient(nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- c.Run(ctx, client) }()

	// read initial Reset Query
	clientReadQuery(t, server, 8)

	// close server side to cause I/O error (ctx still active)
	server.Close()

	select {
	case <-done:
		// Run returned due to I/O error, good
	case <-time.After(time.Second):
		t.Fatal("Run did not return after conn close")
	}

	// verify the client is not connected (Run's defer already ran)
	c.mu.Lock()
	conn := c.conn
	c.mu.Unlock()
	require.Nil(t, conn, "conn should be nil after Run exits")
}

// --- Concurrent SendSerial test ---

func TestSendSerial_ConcurrentWithRun(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	eodSignal, eodCh := waitChan(1)
	c := NewClient(&Options{
		Version:     VersionAuto,
		OnEndOfData: func(_ uint16, _ uint32) { eodSignal() },
	})
	ctx, cancel := ctxWithTimeout(t)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- c.Run(ctx, client) }()

	// read initial Reset Query
	clientReadQuery(t, server, 8)

	// set up initial cache so SendSerial works
	serverWrite(t, server,
		buildCacheResponse(VersionV1, 0x0001),
		buildIPv4Prefix(VersionV1, FlagAnnounce, 24, 24, [4]byte{1, 0, 0, 0}, 65001),
		buildEndOfData(VersionV1, 0x0001, 10, 3600, 600, 7200),
	)
	<-eodCh

	// drain server side so writes don't block on the synchronous net.Pipe
	go func() {
		buf := make([]byte, 4096)
		for {
			if _, err := server.Read(buf); err != nil {
				return
			}
		}
	}()

	// call SendSerial concurrently — this would race without wmu
	var wg sync.WaitGroup
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.SendSerial()
		}()
	}
	wg.Wait()

	cancel()
	<-done
}

// --- Reconnection state test ---

func TestRun_ReconnectionPreservesSerial(t *testing.T) {
	// first connection: establish serial state
	client1, server1 := net.Pipe()
	eodSignal, eodCh := waitChan(1)
	c := NewClient(&Options{
		Version:     VersionAuto,
		OnEndOfData: func(_ uint16, _ uint32) { eodSignal() },
	})
	ctx1, cancel1 := ctxWithTimeout(t)

	done1 := make(chan error, 1)
	go func() { done1 <- c.Run(ctx1, client1) }()

	clientReadQuery(t, server1, 8) // consume Reset Query
	serverWrite(t, server1,
		buildCacheResponse(VersionV1, 0x0001),
		buildEndOfData(VersionV1, 0x0001, 42, 3600, 600, 7200),
	)
	<-eodCh

	// verify state was set
	c.mu.Lock()
	require.True(t, c.hasSerial)
	require.Equal(t, uint32(42), c.serial)
	c.mu.Unlock()

	cancel1()
	<-done1
	server1.Close()

	// second connection: state should persist
	client2, server2 := net.Pipe()
	defer server2.Close()
	ctx2, cancel2 := ctxWithTimeout(t)
	defer cancel2()

	done2 := make(chan error, 1)
	go func() { done2 <- c.Run(ctx2, client2) }()

	// client should still send Reset Query (version auto-negotiation)
	q := clientReadQuery(t, server2, 8)
	require.Equal(t, byte(PDUResetQuery), q[1])

	// verify serial persisted across reconnection
	c.mu.Lock()
	require.True(t, c.hasSerial)
	require.Equal(t, uint32(42), c.serial)
	c.mu.Unlock()

	cancel2()
	<-done2
}

// ctxWithTimeout returns a context with a 5-second timeout for tests.
func ctxWithTimeout(t *testing.T) (context.Context, context.CancelFunc) {
	t.Helper()
	return context.WithTimeout(context.Background(), 5*time.Second)
}

// waitChan returns a channel that is closed after n sends.
// Call the returned function from a callback to signal completion.
func waitChan(n int) (signal func(), ch <-chan struct{}) {
	c := make(chan struct{})
	var cnt int
	var mu sync.Mutex
	return func() {
		mu.Lock()
		cnt++
		if cnt >= n {
			select {
			case <-c:
			default:
				close(c)
			}
		}
		mu.Unlock()
	}, c
}
