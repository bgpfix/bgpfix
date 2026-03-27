package rtr

import (
	"encoding/binary"
	"fmt"
	"io"
)

// PDU type codes.
// Direction: S=Server→Client, C=Client→Server.
const (
	PDUSerialNotify  byte = 0  // S: new data available since serial
	PDUSerialQuery   byte = 1  // C: request incremental update since serial
	PDUResetQuery    byte = 2  // C: request full cache
	PDUCacheResponse byte = 3  // S: begin data stream
	PDUIPv4Prefix    byte = 4  // S: IPv4 ROA entry
	PDUIPv6Prefix    byte = 6  // S: IPv6 ROA entry
	PDUEndOfData     byte = 7  // S: end of data batch; cache is now consistent
	PDUCacheReset    byte = 8  // S: full refresh required; send Reset Query
	PDURouterKey     byte = 9  // S: BGPsec Router Key (not used by this client)
	PDUErrorReport   byte = 10 // S: error notification
	PDUAspa          byte = 11 // S: ASPA entry (RTR v2 only)
)

// Flags for announcement/withdrawal PDUs (IPv4 Prefix, IPv6 Prefix, ASPA).
const (
	FlagAnnounce byte = 1 // record is being added
	FlagWithdraw byte = 0 // record is being removed
)

// RTR protocol version numbers.
const (
	VersionV0 byte = 0 // original (draft-ietf-sidr-rpki-rtr)
	VersionV1 byte = 1 // RFC 8210
	VersionV2 byte = 2 // draft-ietf-sidrops-8210bis (adds ASPA)
)

// Error codes from Error Report PDUs.
const (
	ErrCorruptData  uint16 = 0 // corrupt data received
	ErrInternal     uint16 = 1 // internal error
	ErrNoData       uint16 = 2 // no data available (non-fatal, server still initializing)
	ErrInvalidReq   uint16 = 3 // invalid request
	ErrUnsupVersion uint16 = 4 // unsupported protocol version (non-fatal, triggers downgrade)
	ErrUnsupPDUType uint16 = 5 // unsupported PDU type
	ErrWithdrawUnk  uint16 = 6 // withdrawal of unknown record
	ErrDupAnnounce  uint16 = 7 // duplicate announcement
	ErrUnexpVersion uint16 = 8 // unexpected protocol version
	ErrASPAProvList uint16 = 9 // ASPA provider list error
)

// pduHeader represents the common 8-byte RTR PDU header.
//
// All PDUs begin with:
//
//	version(1) | type(1) | session/flags(2) | length(4)
//
// The session/flags field carries:
//   - Session ID for: SerialNotify, SerialQuery, CacheResponse, EndOfData
//   - Error Code for: ErrorReport
//   - Flags for: IPv4Prefix, IPv6Prefix, ASPA (low byte = flags, high byte unused or reserved)
//     NB: for ASPA, flags is in the HIGH byte (buf[2]) per draft-ietf-sidrops-8210bis §6.12
//   - Zero for: ResetQuery, CacheReset, RouterKey
type pduHeader struct {
	Version byte
	Type    byte
	Session uint16 // session ID, error code, or flags depending on type
	Length  uint32 // total PDU size in bytes including this 8-byte header
}

// readHeader reads the 8-byte common PDU header from r.
func readHeader(r io.Reader) (pduHeader, error) {
	var buf [8]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return pduHeader{}, err
	}
	return pduHeader{
		Version: buf[0],
		Type:    buf[1],
		Session: binary.BigEndian.Uint16(buf[2:4]),
		Length:  binary.BigEndian.Uint32(buf[4:8]),
	}, nil
}

// readPayload reads the PDU payload (h.Length - 8 bytes) from r.
// Returns nil, nil when the PDU has no payload (header-only PDUs).
func readPayload(r io.Reader, h pduHeader) ([]byte, error) {
	if h.Length < 8 {
		return nil, fmt.Errorf("rtr: type %d length %d < 8", h.Type, h.Length)
	}
	if h.Length == 8 {
		return nil, nil
	}
	payload := make([]byte, h.Length-8)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, fmt.Errorf("rtr: type %d payload read: %w", h.Type, err)
	}
	return payload, nil
}

// writeResetQuery writes a Reset Query PDU (type 2, 8 bytes) to w.
func writeResetQuery(w io.Writer, version byte) error {
	_, err := w.Write([]byte{version, PDUResetQuery, 0, 0, 0, 0, 0, 8})
	return err
}

// writeSerialQuery writes a Serial Query PDU (type 1, 12 bytes) to w.
func writeSerialQuery(w io.Writer, version byte, sessid uint16, serial uint32) error {
	var buf [12]byte
	buf[0] = version
	buf[1] = PDUSerialQuery
	binary.BigEndian.PutUint16(buf[2:4], sessid)
	binary.BigEndian.PutUint32(buf[4:8], 12)
	binary.BigEndian.PutUint32(buf[8:12], serial)
	_, err := w.Write(buf[:])
	return err
}

// parseErrorText extracts the error message text from an Error Report payload.
// payload is the bytes after the 8-byte PDU header.
//
// Error Report payload layout:
//
//	encPDULen(4) | encPDU(encPDULen) | textLen(4) | text(textLen)
func parseErrorText(payload []byte) string {
	if len(payload) < 4 {
		return ""
	}
	encLen := int(binary.BigEndian.Uint32(payload[0:4]))
	off := 4 + encLen
	if off+4 > len(payload) {
		return ""
	}
	textLen := int(binary.BigEndian.Uint32(payload[off : off+4]))
	off += 4
	if off+textLen > len(payload) || textLen == 0 {
		return ""
	}
	return string(payload[off : off+textLen])
}
