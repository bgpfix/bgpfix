// Package msg - Wire format tests for BGP message parsing
// Tests RFC 4271 compliance and compatibility with FRR/BIRD/GoBGP
package msg

import (
	"bytes"
	"io"
	"net/netip"
	"testing"

	"github.com/bgpfix/bgpfix/caps"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// Test Helper Functions
// ============================================================================

// makeHeader creates a BGP message with given total length and type
func makeHeader(totalLen uint16, typ Type) []byte {
	buf := make([]byte, HEADLEN)
	copy(buf, BgpMarker)
	buf[16] = byte(totalLen >> 8)
	buf[17] = byte(totalLen)
	buf[18] = byte(typ)
	return buf
}

// makeMsg creates a complete BGP message with header + data
func makeMsg(typ Type, data []byte) []byte {
	totalLen := uint16(HEADLEN + len(data))
	header := makeHeader(totalLen, typ)
	return append(header, data...)
}

// makeCapability creates a capability TLV (type, length, value)
func makeCapability(code byte, data []byte) []byte {
	return append([]byte{code, byte(len(data))}, data...)
}

// makeParam creates an optional parameter (type=2 for capabilities)
func makeParam(caps []byte) []byte {
	return append([]byte{PARAM_CAPS, byte(len(caps))}, caps...)
}

// makeOpenData creates OPEN message data (without header)
func makeOpenData(asn uint16, holdTime uint16, bgpID [4]byte, params []byte) []byte {
	data := []byte{
		OPEN_VERSION,                           // version = 4
		byte(asn >> 8),                         // ASN high byte
		byte(asn),                              // ASN low byte
		byte(holdTime >> 8),                    // hold time high
		byte(holdTime),                         // hold time low
		bgpID[0], bgpID[1], bgpID[2], bgpID[3], // BGP ID
		byte(len(params)), // params length
	}
	return append(data, params...)
}

// makeUpdateData creates UPDATE message data (without header)
func makeUpdateData(withdrawn, attrs, nlri []byte) []byte {
	wlen := uint16(len(withdrawn))
	alen := uint16(len(attrs))
	data := []byte{byte(wlen >> 8), byte(wlen)}
	data = append(data, withdrawn...)
	data = append(data, byte(alen>>8), byte(alen))
	data = append(data, attrs...)
	return append(data, nlri...)
}

// makeAttr creates a path attribute with flags, type code, and value
func makeAttr(flags, code byte, value []byte) []byte {
	if flags&0x10 != 0 { // extended length
		return append([]byte{flags, code, byte(len(value) >> 8), byte(len(value))}, value...)
	}
	return append([]byte{flags, code, byte(len(value))}, value...)
}

// ============================================================================
// BGP Header Tests (RFC 4271 Section 4.1)
// ============================================================================

func TestHeader_ValidMessages(t *testing.T) {
	tests := []struct {
		name    string
		raw     []byte
		wantLen int
		wantTyp Type
	}{
		{
			name:    "valid KEEPALIVE (19 bytes)",
			raw:     makeHeader(HEADLEN, KEEPALIVE),
			wantLen: HEADLEN,
			wantTyp: KEEPALIVE,
		},
		{
			name:    "valid OPEN header",
			raw:     makeHeader(29, OPEN), // minimum OPEN
			wantLen: HEADLEN,
			wantTyp: OPEN,
		},
		{
			name:    "valid UPDATE header",
			raw:     makeHeader(23, UPDATE), // minimum UPDATE
			wantLen: HEADLEN,
			wantTyp: UPDATE,
		},
		{
			name:    "valid NOTIFICATION header",
			raw:     makeHeader(21, NOTIFY), // minimum NOTIFY
			wantLen: HEADLEN,
			wantTyp: NOTIFY,
		},
		{
			name:    "valid ROUTE-REFRESH header",
			raw:     makeHeader(23, REFRESH),
			wantLen: HEADLEN,
			wantTyp: REFRESH,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Extend buffer to declared length
			buf := make([]byte, int(tt.raw[16])<<8|int(tt.raw[17]))
			copy(buf, tt.raw)

			msg := NewMsg()
			off, err := msg.FromBytes(buf)
			require.NoError(t, err)
			require.Equal(t, len(buf), off)
			require.Equal(t, tt.wantTyp, msg.Type)
		})
	}
}

func TestHeader_InvalidMarker(t *testing.T) {
	tests := []struct {
		name   string
		marker []byte
	}{
		{"all zeros", make([]byte, 16)},
		{"last byte wrong", append(bytes.Repeat([]byte{0xff}, 15), 0x00)},
		{"first byte wrong", append([]byte{0x00}, bytes.Repeat([]byte{0xff}, 15)...)},
		{"middle byte wrong", func() []byte {
			m := bytes.Repeat([]byte{0xff}, 16)
			m[8] = 0x00
			return m
		}()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := append(tt.marker, 0x00, HEADLEN, byte(KEEPALIVE))
			msg := NewMsg()
			_, err := msg.FromBytes(buf)
			require.ErrorIs(t, err, ErrMarker)
		})
	}
}

func TestHeader_InvalidLength(t *testing.T) {
	tests := []struct {
		name    string
		length  uint16
		wantErr error
	}{
		{"length 0", 0, ErrLength},
		{"length 18 (below minimum)", 18, ErrLength},
		// Note: length > 4096 is valid with RFC 8654 extended message support
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := makeHeader(tt.length, KEEPALIVE)
			// Extend buffer if needed
			if len(buf) < int(tt.length) {
				buf = append(buf, make([]byte, int(tt.length)-len(buf))...)
			}
			msg := NewMsg()
			_, err := msg.FromBytes(buf)
			require.ErrorIs(t, err, tt.wantErr)
		})
	}
}

func TestHeader_TruncatedBuffer(t *testing.T) {
	tests := []struct {
		name string
		buf  []byte
	}{
		{"empty buffer", []byte{}},
		{"1 byte", []byte{0xff}},
		{"18 bytes (one short)", bytes.Repeat([]byte{0xff}, 18)},
		{"header declares 100, only 19 present", makeHeader(100, OPEN)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := NewMsg()
			_, err := msg.FromBytes(tt.buf)
			require.ErrorIs(t, err, io.ErrUnexpectedEOF)
		})
	}
}

// Accept extra bytes after a complete message (stream parsing)
func TestHeader_ExtraBytes(t *testing.T) {
	raw := makeHeader(HEADLEN, KEEPALIVE)
	buf := append(raw, 0x00, 0x01)

	msg := NewMsg()
	off, err := msg.FromBytes(buf)
	require.NoError(t, err)
	require.Equal(t, HEADLEN, off)
	require.Equal(t, KEEPALIVE, msg.Type)
	require.Empty(t, msg.Data)
}

// ============================================================================
// OPEN Message Tests (RFC 4271 Section 4.2)
// ============================================================================

func TestOpen_ValidMinimal(t *testing.T) {
	// Minimal OPEN: version=4, ASN=65001, hold=90, ID=192.0.2.1, no params
	bgpID := [4]byte{192, 0, 2, 1}
	data := makeOpenData(65001, 90, bgpID, nil)
	raw := makeMsg(OPEN, data)

	msg := NewMsg()
	off, err := msg.FromBytes(raw)
	require.NoError(t, err)
	require.Equal(t, len(raw), off)
	require.Equal(t, OPEN, msg.Type)

	// Parse upper layer
	err = msg.Open.Parse()
	require.NoError(t, err)
	require.Equal(t, byte(4), msg.Open.Version)
	require.Equal(t, uint16(65001), msg.Open.ASN)
	require.Equal(t, uint16(90), msg.Open.HoldTime)
	require.Equal(t, netip.AddrFrom4(bgpID), msg.Open.Identifier)
	require.Empty(t, msg.Open.ParamsRaw)
}

func TestOpen_WithAS4Capability(t *testing.T) {
	// OPEN with AS4 capability (4-byte ASN = 4200000001)
	bgpID := [4]byte{10, 0, 0, 1}
	as4Cap := makeCapability(65, []byte{0xFA, 0x56, 0xEA, 0x01}) // AS 4200000001
	params := makeParam(as4Cap)
	data := makeOpenData(AS_TRANS, 180, bgpID, params) // ASN=23456 (AS_TRANS)
	raw := makeMsg(OPEN, data)

	msg := NewMsg()
	_, err := msg.FromBytes(raw)
	require.NoError(t, err)

	err = msg.Open.Parse()
	require.NoError(t, err)
	require.Equal(t, uint16(AS_TRANS), msg.Open.ASN)
	require.NotEmpty(t, msg.Open.ParamsRaw)

	err = msg.Open.ParseCaps()
	require.NoError(t, err)
	require.Equal(t, 4200000001, msg.Open.GetASN()) // Should return AS4 value
}

func TestOpen_WithMultipleCaps(t *testing.T) {
	// OPEN with MP-BGP (IPv4 unicast), AS4, Route-Refresh
	bgpID := [4]byte{172, 16, 0, 1}

	mpCap := makeCapability(1, []byte{0x00, 0x01, 0x00, 0x01})   // AFI=1, SAFI=1
	as4Cap := makeCapability(65, []byte{0x00, 0x00, 0xFD, 0xE9}) // AS 65001
	rrCap := makeCapability(2, []byte{})                         // Route-Refresh

	allCaps := append(mpCap, as4Cap...)
	allCaps = append(allCaps, rrCap...)
	params := makeParam(allCaps)
	data := makeOpenData(65001, 90, bgpID, params)
	raw := makeMsg(OPEN, data)

	msg := NewMsg()
	_, err := msg.FromBytes(raw)
	require.NoError(t, err)

	err = msg.Open.Parse()
	require.NoError(t, err)

	err = msg.Open.ParseCaps()
	require.NoError(t, err)
	require.Equal(t, 3, msg.Open.Caps.Len())
}

func TestOpen_InvalidVersion(t *testing.T) {
	tests := []struct {
		name    string
		version byte
	}{
		{"version 3", 3},
		{"version 5", 5},
		{"version 0", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bgpID := [4]byte{192, 0, 2, 1}
			data := makeOpenData(65001, 90, bgpID, nil)
			data[0] = tt.version // Override version
			raw := makeMsg(OPEN, data)

			msg := NewMsg()
			_, err := msg.FromBytes(raw)
			require.NoError(t, err)

			err = msg.Open.Parse()
			require.ErrorIs(t, err, ErrVersion)
		})
	}
}

func TestOpen_HoldTimeEdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		holdTime uint16
	}{
		{"hold time 0 (no keepalives)", 0},
		{"hold time 3 (minimum per RFC)", 3},
		{"hold time 65535 (maximum)", 65535},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bgpID := [4]byte{192, 0, 2, 1}
			data := makeOpenData(65001, tt.holdTime, bgpID, nil)
			raw := makeMsg(OPEN, data)

			msg := NewMsg()
			_, err := msg.FromBytes(raw)
			require.NoError(t, err)

			err = msg.Open.Parse()
			require.NoError(t, err)
			require.Equal(t, tt.holdTime, msg.Open.HoldTime)
		})
	}
}

func TestOpen_TruncatedParams(t *testing.T) {
	bgpID := [4]byte{192, 0, 2, 1}
	// Declare 10 bytes of params but only provide 5
	data := makeOpenData(65001, 90, bgpID, []byte{0x02, 0x06, 0x01, 0x04, 0x00})
	data[9] = 10 // Override params length to be wrong
	raw := makeMsg(OPEN, data)

	msg := NewMsg()
	// Adjust header length
	raw[16] = 0
	raw[17] = byte(HEADLEN + len(data))

	_, err := msg.FromBytes(raw)
	require.NoError(t, err)

	err = msg.Open.Parse()
	require.ErrorIs(t, err, ErrParams)
}

// ============================================================================
// UPDATE Message Tests (RFC 4271 Section 4.3)
// ============================================================================

func TestUpdate_Empty(t *testing.T) {
	// Empty UPDATE: no withdrawn, no attrs, no NLRI
	data := makeUpdateData(nil, nil, nil)
	raw := makeMsg(UPDATE, data)

	msg := NewMsg()
	_, err := msg.FromBytes(raw)
	require.NoError(t, err)

	var cps caps.Caps
	err = msg.Update.Parse(cps)
	require.NoError(t, err)
	require.Empty(t, msg.Update.Reach)
	require.Empty(t, msg.Update.Unreach)
}

func TestUpdate_SingleWithdrawal(t *testing.T) {
	// Withdraw 192.0.2.0/24
	withdrawn := []byte{24, 192, 0, 2} // length=24, prefix
	data := makeUpdateData(withdrawn, nil, nil)
	raw := makeMsg(UPDATE, data)

	msg := NewMsg()
	_, err := msg.FromBytes(raw)
	require.NoError(t, err)

	var cps caps.Caps
	err = msg.Update.Parse(cps)
	require.NoError(t, err)
	require.Len(t, msg.Update.Unreach, 1)
	require.Equal(t, "192.0.2.0/24", msg.Update.Unreach[0].Prefix.String())
}

func TestUpdate_SingleAnnouncement(t *testing.T) {
	// Announce 10.0.0.0/8 with basic attributes
	// ORIGIN IGP (0x40, 0x01, 0x01, 0x00)
	origin := makeAttr(0x40, 1, []byte{0x00})
	// AS_PATH empty (0x40, 0x02, 0x00)
	asPath := makeAttr(0x40, 2, []byte{})
	// NEXT_HOP 192.0.2.1 (0x40, 0x03, 0x04, ...)
	nextHop := makeAttr(0x40, 3, []byte{192, 0, 2, 1})

	attrs := append(origin, asPath...)
	attrs = append(attrs, nextHop...)
	nlri := []byte{8, 10} // 10.0.0.0/8

	data := makeUpdateData(nil, attrs, nlri)
	raw := makeMsg(UPDATE, data)

	msg := NewMsg()
	_, err := msg.FromBytes(raw)
	require.NoError(t, err)

	var cps caps.Caps
	err = msg.Update.Parse(cps)
	require.NoError(t, err)
	require.Len(t, msg.Update.Reach, 1)
	require.Equal(t, "10.0.0.0/8", msg.Update.Reach[0].Prefix.String())
}

func TestUpdate_MultipleNLRI(t *testing.T) {
	// Multiple prefixes: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
	origin := makeAttr(0x40, 1, []byte{0x00})
	asPath := makeAttr(0x40, 2, []byte{})
	nextHop := makeAttr(0x40, 3, []byte{192, 0, 2, 1})
	attrs := append(origin, asPath...)
	attrs = append(attrs, nextHop...)

	nlri := []byte{
		8, 10, // 10.0.0.0/8
		12, 172, 16, // 172.16.0.0/12
		16, 192, 168, // 192.168.0.0/16
	}

	data := makeUpdateData(nil, attrs, nlri)
	raw := makeMsg(UPDATE, data)

	msg := NewMsg()
	_, err := msg.FromBytes(raw)
	require.NoError(t, err)

	var cps caps.Caps
	err = msg.Update.Parse(cps)
	require.NoError(t, err)
	require.Len(t, msg.Update.Reach, 3)
}

// ============================================================================
// KEEPALIVE Tests (RFC 4271 Section 4.4)
// ============================================================================

func TestKeepalive_Valid(t *testing.T) {
	raw := makeHeader(HEADLEN, KEEPALIVE)

	msg := NewMsg()
	off, err := msg.FromBytes(raw)
	require.NoError(t, err)
	require.Equal(t, HEADLEN, off)
	require.Equal(t, KEEPALIVE, msg.Type)
	require.Empty(t, msg.Data)
}

// Minimal NOTIFICATION: error code + subcode
func TestNotify_Minimal(t *testing.T) {
	data := []byte{1, 2}
	raw := makeMsg(NOTIFY, data)

	msg := NewMsg()
	off, err := msg.FromBytes(raw)
	require.NoError(t, err)
	require.Equal(t, len(raw), off)
	require.Equal(t, NOTIFY, msg.Type)
	require.Equal(t, data, msg.Data)
}

// Minimal ROUTE-REFRESH: AFI(2) + Reserved(1) + SAFI(1)
func TestRefresh_Minimal(t *testing.T) {
	data := []byte{0x00, 0x01, 0x00, 0x01}
	raw := makeMsg(REFRESH, data)

	msg := NewMsg()
	off, err := msg.FromBytes(raw)
	require.NoError(t, err)
	require.Equal(t, len(raw), off)
	require.Equal(t, REFRESH, msg.Type)
	require.Equal(t, data, msg.Data)
}
