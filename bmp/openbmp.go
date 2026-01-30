package bmp

import (
	"io"
	"net/netip"
	"time"

	"github.com/bgpfix/bgpfix/msg"
	"github.com/bgpfix/bgpfix/pipe"
)

// OpenBMP header constants
const (
	OPENBMP_MAGIC      = "OBMP"
	OPENBMP_VERSION    = 0x01 // protocol version
	OPENBMP_HEADLEN    = 14   // minimum header length to read basic fields
	OPENBMP_FLAG_V6    = 0x40 // router IP is IPv6
	OPENBMP_FLAG_RTYPE = 0x80 // router message (vs collector message)
	OPENBMP_OBJ_RAW    = 12   // object type for BMP_RAW
	OPENBMP_OBJ_ROUTER = 1    // object type for router
	OPENBMP_OBJ_PEER   = 2    // object type for peer
)

// OpenBmp represents an OpenBMP message header (used by RouteViews Kafka streams).
// See: https://github.com/SNAS/openbmp and https://www.openbmp.org/api/kafka_message_schema.html
//
// Binary header format v1.7:
//
//	OBMP (4 bytes): Magic number
//	Major (1 byte): Version major (should be 1)
//	Minor (1 byte): Version minor (7 for bmp_raw)
//	Header Length (2 bytes BE): Total header length
//	Data Length (4 bytes BE): BMP message length that follows
//	Flags (1 byte): 0x80=router msg, 0x40=IPv6
//	Object Type (1 byte): 12=BMP_RAW, 1=router, 2=peer, etc.
//	Timestamp sec (4 bytes BE)
//	Timestamp usec (4 bytes BE)
//	Collector Hash (16 bytes): MD5 hash
//	Collector Name Len (2 bytes BE)
//	Collector Name (variable)
//	Router Hash (16 bytes): MD5 hash
//	Router IP (16 bytes): IPv4 (last 4 bytes) or IPv6
//	Router Name Len (2 bytes BE)
//	Router Name (variable)
//	Row Count (4 bytes): ignored
//	[at offset HeaderLen]: BMP Message (DataLen bytes)
type OpenBmp struct {
	ref bool   // true iff Data is a reference to borrowed memory
	buf []byte // internal buffer

	Version   uint8  // protocol version (major.minor encoded: major=byte5, minor=byte6)
	Minor     uint8  // version minor
	HeaderLen uint16 // total header length
	DataLen   uint32 // BMP message length
	Flags     uint8  // message flags
	ObjType   uint8  // object type (12 = BMP_RAW)

	// Timestamps from OpenBMP header (not from BMP peer header)
	Time time.Time

	// Collector info
	CollectorHash [16]byte
	CollectorName string

	// Router info
	RouterHash [16]byte
	RouterIP   netip.Addr
	RouterName string

	// BMP message data
	Data []byte
}

// NewOpenBmp returns a new empty OpenBMP message
func NewOpenBmp() *OpenBmp {
	return new(OpenBmp)
}

// Reset clears the message
func (o *OpenBmp) Reset() *OpenBmp {
	o.ref = false
	if cap(o.buf) < 1024*1024 {
		o.buf = o.buf[:0]
	} else {
		o.buf = nil
	}

	o.Version = 0
	o.Minor = 0
	o.HeaderLen = 0
	o.DataLen = 0
	o.Flags = 0
	o.ObjType = 0
	o.Time = time.Time{}
	o.CollectorHash = [16]byte{}
	o.CollectorName = ""
	o.RouterHash = [16]byte{}
	o.RouterIP = netip.Addr{}
	o.RouterName = ""
	o.Data = nil

	return o
}

// FromBytes parses the OpenBMP message from raw bytes.
// Does not copy data. Returns the number of bytes consumed.
func (o *OpenBmp) FromBytes(raw []byte) (int, error) {
	if len(raw) < OPENBMP_HEADLEN {
		return 0, ErrShort
	}

	// Check magic
	if string(raw[0:4]) != OPENBMP_MAGIC {
		return 0, ErrOpenBmpMagic
	}

	o.Version = raw[4]
	if o.Version != OPENBMP_VERSION {
		return 0, ErrOpenBmpVersion
	}

	o.Minor = raw[5]
	o.HeaderLen = msb.Uint16(raw[6:8])
	o.DataLen = msb.Uint32(raw[8:12])
	o.Flags = raw[12]
	o.ObjType = raw[13]

	// Validate header length
	if len(raw) < int(o.HeaderLen) {
		return 0, ErrShort
	}

	// Validate total length (careful with overflow)
	totalLen := int(o.HeaderLen) + int(o.DataLen)
	if totalLen < int(o.HeaderLen) {
		return 0, ErrLength
	}
	if totalLen > len(raw) {
		return 0, ErrShort
	}

	// Parse extended header fields for BMP_RAW messages
	off := 14
	if o.ObjType == OPENBMP_OBJ_RAW && int(o.HeaderLen) > off {
		// Timestamps
		if off+8 <= int(o.HeaderLen) {
			sec := msb.Uint32(raw[off : off+4])
			usec := msb.Uint32(raw[off+4 : off+8])
			o.Time = time.Unix(int64(sec), int64(usec)*1000).UTC()
			off += 8
		}

		// Collector hash (16 bytes)
		if off+16 <= int(o.HeaderLen) {
			copy(o.CollectorHash[:], raw[off:off+16])
			off += 16
		}

		// Collector name (length-prefixed string)
		if off+2 <= int(o.HeaderLen) {
			nameLen := int(msb.Uint16(raw[off : off+2]))
			off += 2
			if off+nameLen <= int(o.HeaderLen) {
				o.CollectorName = string(raw[off : off+nameLen])
				off += nameLen
			}
		}

		// Router hash (16 bytes)
		if off+16 <= int(o.HeaderLen) {
			copy(o.RouterHash[:], raw[off:off+16])
			off += 16
		}

		// Router IP (16 bytes, IPv4 in last 4 bytes)
		if off+16 <= int(o.HeaderLen) {
			if o.Flags&OPENBMP_FLAG_V6 != 0 {
				o.RouterIP = netip.AddrFrom16([16]byte(raw[off : off+16]))
			} else {
				o.RouterIP = netip.AddrFrom4([4]byte(raw[off+12 : off+16]))
			}
			off += 16
		}

		// Router name (length-prefixed string)
		if off+2 <= int(o.HeaderLen) {
			nameLen := int(msb.Uint16(raw[off : off+2]))
			off += 2
			if off+nameLen <= int(o.HeaderLen) {
				o.RouterName = string(raw[off : off+nameLen])
				off += nameLen
			}
		}

		// Row count (4 bytes) - should be 1 for BMP_RAW
		if off+4 <= int(o.HeaderLen) {
			rowCount := msb.Uint32(raw[off : off+4])
			if rowCount != 1 {
				return 0, ErrOpenBmpRowCount
			}
		}
	}

	// Extract BMP data
	o.ref = true
	o.Data = raw[o.HeaderLen:totalLen]

	return totalLen, nil
}

// CopyData copies referenced data if needed, making OpenBmp the owner
func (o *OpenBmp) CopyData() *OpenBmp {
	if !o.ref || o.Data == nil {
		return o
	}
	o.ref = false
	o.buf = append(o.buf[:0], o.Data...)
	o.Data = o.buf
	return o
}

// IsRouterMessage returns true if this is a router message (vs collector)
func (o *OpenBmp) IsRouterMessage() bool {
	return o.Flags&OPENBMP_FLAG_RTYPE != 0
}

// IsRouterIPv6 returns true if the router IP is IPv6
func (o *OpenBmp) IsRouterIPv6() bool {
	return o.Flags&OPENBMP_FLAG_V6 != 0
}

// IsBmpRaw returns true if this contains raw BMP data
func (o *OpenBmp) IsBmpRaw() bool {
	return o.ObjType == OPENBMP_OBJ_RAW
}

// Marshal serializes the OpenBMP message to o.buf.
// Data must already contain the BMP message.
func (o *OpenBmp) Marshal() error {
	if o.Data == nil {
		return ErrNoData
	}

	// calculate header length (minimal: 14 + timestamps + hashes + names)
	headerLen := 14 + 8 + 16 + 2 + len(o.CollectorName) + 16 + 16 + 2 + len(o.RouterName) + 4

	// allocate buffer
	total := headerLen + len(o.Data)
	if cap(o.buf) < total {
		o.buf = make([]byte, total)
	}
	o.buf = o.buf[:total]

	// magic + version
	copy(o.buf[0:4], OPENBMP_MAGIC)
	o.buf[4] = OPENBMP_VERSION
	o.buf[5] = 7 // minor version for bmp_raw
	msb.PutUint16(o.buf[6:8], uint16(headerLen))
	msb.PutUint32(o.buf[8:12], uint32(len(o.Data)))
	o.buf[12] = o.Flags
	o.buf[13] = OPENBMP_OBJ_RAW

	off := 14

	// timestamp
	sec := o.Time.Unix()
	usec := o.Time.UnixMicro() % 1e6
	msb.PutUint32(o.buf[off:], uint32(sec))
	msb.PutUint32(o.buf[off+4:], uint32(usec))
	off += 8

	// collector hash + name
	copy(o.buf[off:], o.CollectorHash[:])
	off += 16
	msb.PutUint16(o.buf[off:], uint16(len(o.CollectorName)))
	off += 2
	copy(o.buf[off:], o.CollectorName)
	off += len(o.CollectorName)

	// router hash + ip + name
	copy(o.buf[off:], o.RouterHash[:])
	off += 16
	clear(o.buf[off : off+16])
	if o.RouterIP.IsValid() {
		if o.RouterIP.Is6() {
			o.Flags |= OPENBMP_FLAG_V6
			copy(o.buf[off:], o.RouterIP.AsSlice())
		} else {
			o.Flags &^= OPENBMP_FLAG_V6
			copy(o.buf[off+12:], o.RouterIP.AsSlice())
		}
		o.buf[12] = o.Flags // update flags byte after IP detection
	}
	off += 16
	msb.PutUint16(o.buf[off:], uint16(len(o.RouterName)))
	off += 2
	copy(o.buf[off:], o.RouterName)
	off += len(o.RouterName)

	// row count = 1
	msb.PutUint32(o.buf[off:], 1)
	off += 4

	// BMP data
	copy(o.buf[off:], o.Data)

	o.HeaderLen = uint16(headerLen)
	o.DataLen = uint32(len(o.Data))
	return nil
}

// WriteTo writes the OpenBMP message to w.
func (o *OpenBmp) WriteTo(w io.Writer) (int64, error) {
	if len(o.buf) == 0 {
		return 0, ErrNoData
	}
	n, err := w.Write(o.buf)
	return int64(n), err
}

// FromBmp wraps marshaled BMP message for OpenBMP output.
// bm must already be marshaled. Extracts collector/router from message tags.
func (o *OpenBmp) FromBmp(bm *Bmp, m *msg.Msg) error {
	o.ObjType = OPENBMP_OBJ_RAW
	o.Time = m.Time
	o.Data = bm.Bytes()

	// Extract collector/router from message tags
	if tags := pipe.GetTags(m); len(tags) > 0 {
		o.CollectorName = tags["COLLECTOR"]
		if router := tags["ROUTER"]; router != "" {
			if addr, err := netip.ParseAddr(router); err == nil {
				o.RouterIP = addr
			} else {
				o.RouterName = router
			}
		}
	}

	return nil
}
