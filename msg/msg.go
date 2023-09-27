// Package msg represents BGP messages.
//
// This package can read/write BGP messages in wire and JSON formats.
package msg

import (
	"bytes"
	"io"
	"strconv"
	"time"

	"github.com/bgpfix/bgpfix/binary"
	"github.com/bgpfix/bgpfix/caps"
	"github.com/bgpfix/bgpfix/json"
)

// Msg represents a BGP message.
// Use NewMsg to get a new valid object.
type Msg struct {
	// internal

	ref bool   // true iff Data is a reference we don't own
	buf []byte // internal buffer

	// optional metadata

	Dst  Dst       // message destination
	Seq  int64     // sequence number
	Time time.Time // message timestamp

	// raw contents

	Type Type   // message type
	Data []byte // message data (referenced or owned), can be nil

	// upper layer

	Upper  Type   // which of the upper layer is valid?
	Dirty  bool   // if true, probably needs a marshal (Data does not reflect Upper)
	Open   Open   // parsed BGP OPEN message
	Update Update // parsed BGP UPDATE message

	// for optional use beyond this pkg

	Value Value // NB: not affected by Reset()
}

// Value represents an optional, arbitrary value attached to a message
type Value interface {
	// ToJSON appends JSON representation of the value to dst
	ToJSON(dst []byte) []byte

	// FromJSON reads from JSON representation in src
	FromJSON(src []byte) error
}

// BGP message destination (message direction)
type Dst byte

//go:generate go run github.com/dmarkham/enumer -type Dst -trimprefix DST_
const (
	DST_LR Dst = 0 // no particular destination (ie. both L and R)
	DST_L  Dst = 1 // destined for L ("left" or "local")
	DST_R  Dst = 2 // destined for R ("right" or "remote")
)

// BGP message type
type Type byte

//go:generate go run github.com/dmarkham/enumer -type Type
const (
	INVALID   Type = 0 // NOT DEFINED / INVALID
	OPEN      Type = 1 // OPEN
	UPDATE    Type = 2 // UPDATE
	NOTIFY    Type = 3 // NOTFICATION
	KEEPALIVE Type = 4 // KEEPALIVE
	REFRESH   Type = 5 // ROUTE-REFRESH RFC2918
)

const (
	// BGP header length, per rfc4271/4.1
	HEADLEN = 19 // = marker(16) + length(2) + type(1)

	// BGP maximum message length, per rfc4271
	MAXLEN = 4096

	// BGP maximum extended message length, per rfc8654
	MAXLEN_EXT = 65535

	// JSON date and time format
	JSON_TIME = `2006-01-02T15:04:05.000`
)

var (
	msb = binary.Msb

	bgp_marker = [...]byte{
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	}
)

// NewMsg returns new empty message
func NewMsg() *Msg {
	msg := new(Msg)
	msg.Open.Init(msg)
	msg.Update.Init(msg)
	return msg
}

// Reset clears the message
func (msg *Msg) Reset() *Msg {
	switch msg.Upper {
	case OPEN:
		msg.Open.Reset()
	case UPDATE:
		msg.Update.Reset()
	}

	msg.ref = false
	if cap(msg.buf) < 1024*1024 {
		msg.buf = msg.buf[:0] // NB: re-use iff < 1MiB
	} else {
		msg.buf = nil
	}

	msg.Dst = 0
	msg.Seq = 0
	msg.Time = time.Time{}

	msg.Type = 0
	msg.Data = nil

	msg.Upper = INVALID
	msg.Dirty = false

	msg.Value = nil

	return msg
}

// Length returns total BGP message length, including header
func (msg *Msg) Length() int {
	return len(msg.Data) + HEADLEN
}

// SetUp prepares to make use of and modify the upper layer of given type.
// Does not reset the upper layer struct, though.
func (msg *Msg) SetUp(typ Type) *Msg {
	msg.Type = typ
	msg.Upper = typ
	msg.Dirty = true
	return msg
}

// SetData updates the data to reference given value
func (msg *Msg) SetData(data []byte) *Msg {
	msg.Data = data
	msg.ref = data != nil
	if msg.Upper != INVALID {
		msg.Dirty = true
	}
	return msg
}

// Own tags msg as the owner of referenced data. Does not copy the data.
func (msg *Msg) Own() *Msg {
	msg.ref = false
	return msg
}

// Disown tags msg as not the owner of data.
func (msg *Msg) Disown() *Msg {
	msg.ref = true
	return msg
}

// CopyData copies the referenced data iff needed and makes msg the owner
func (msg *Msg) CopyData() *Msg {
	if !msg.ref {
		return msg // already owned
	}

	// tag as owned
	msg.ref = false

	// special case: nothing to do
	if msg.Data == nil {
		return msg
	}

	// copy re-using our internal buffer
	msg.buf = append(msg.buf[:0], msg.Data...)
	msg.Data = msg.buf
	msg.ref = false
	return msg
}

// Parse parses the BGP message in raw. Does not copy.
// Returns the number of parsed bytes from raw.
func (msg *Msg) Parse(raw []byte) (off int, err error) {
	// enough data for marker + length + type?
	if len(raw) < HEADLEN {
		return off, io.ErrUnexpectedEOF
	}
	data := raw

	// find marker
	if !bytes.HasPrefix(data, bgp_marker[:]) {
		return off, ErrMarker
	}
	off = len(bgp_marker)
	data = raw[off:]

	// read type and length
	l := int(msb.Uint16(data[:2]))
	msg.Type = Type(data[2])
	off += 3
	data = raw[off:]

	// check length
	dlen := l - HEADLEN
	if dlen < 0 {
		return off, ErrLength
	} else if dlen > len(data) {
		return off, io.ErrUnexpectedEOF
	}

	// reference data, if needed
	if dlen > 0 {
		msg.ref = true
		msg.Data = data[:dlen]
	} else {
		msg.ref = false
		msg.Data = nil
	}

	// done!
	return off + dlen, nil
}

// ParseUpper parses the upper layer iff needed.
// caps can infuence the upper layer decoders.
func (msg *Msg) ParseUpper(caps caps.Caps) error {
	if msg.Upper != INVALID {
		return nil // already done
	}

	var err error
	switch msg.Type {
	case OPEN:
		o := &msg.Open
		err = o.Parse()
		if err != nil {
			break
		}
		err = o.ParseCaps()
	case UPDATE:
		u := &msg.Update
		err = u.Parse()
		if err != nil {
			break
		}
		err = u.ParseAttrs(caps)
	case KEEPALIVE:
		if len(msg.Data) != 0 {
			err = ErrLength
		}
	case NOTIFY, REFRESH:
		// err = ErrNotImpl // TODO
	default:
		err = ErrType
	}

	if err == nil {
		msg.Upper = msg.Type
		msg.Dirty = false
	}

	return err
}

// MarshalUpper marshals the upper layer to msg.Data iff possible and needed.
// caps can infuence the upper layer encoders.
func (msg *Msg) MarshalUpper(caps caps.Caps) error {
	if !msg.Dirty || msg.Upper == INVALID {
		return nil // not needed or not possible
	}

	var err error
	switch msg.Type {
	case OPEN:
		o := &msg.Open
		err = o.MarshalCaps()
		if err != nil {
			break
		}
		err = o.Marshal()
	case UPDATE:
		u := &msg.Update
		err = u.MarshalAttrs(caps)
		if err != nil {
			break
		}
		err = u.Marshal(caps)
	case KEEPALIVE:
		msg.SetData(nil)
	default:
		err = ErrType
	}

	if err == nil {
		msg.Dirty = false
	}

	return err
}

// WriteTo marshals the BGP message to w, implementing io.WriterTo
func (msg *Msg) WriteTo(w io.Writer) (n int64, err error) {
	var m int

	// data length ok?
	l := msg.Length()
	if l > MAXLEN {
		return 0, ErrLength
	}

	// write the marker
	m, err = w.Write(bgp_marker[:])
	if err != nil {
		return
	}
	n += int64(m)

	// write length
	m, err = msb.WriteUint16(w, uint16(l))
	if err != nil {
		return
	}
	n += int64(m)

	// write type
	m, err = msb.WriteUint8(w, uint8(msg.Type))
	if err != nil {
		return
	}
	n += int64(m)

	// write data?
	if len(msg.Data) > 0 {
		m, err = w.Write(msg.Data)
		if err != nil {
			return
		}
		n += int64(m)
	}

	// done
	return
}

// String dumps msg to JSON
func (msg *Msg) String() string {
	return string(msg.ToJSON(nil))
}

// ToJSON appends JSON representation of msg to dst (may be nil to allocate)
func (msg *Msg) ToJSON(dst []byte) []byte {
	dst = append(dst, `["`...)

	// [0] time
	dst = append(dst, msg.Time.Format(JSON_TIME)...)
	dst = append(dst, `",`...)

	// [1] sequence number (for dir)
	dst = strconv.AppendInt(dst, msg.Seq, 10)

	// [2] direction
	dst = append(dst, `,"`...)
	dst = append(dst, msg.Dst.String()...) // TODO: or number

	// [3] type
	dst = append(dst, `","`...)
	dst = append(dst, msg.Type.String()...) // TODO: or number
	dst = append(dst, `",`...)

	// [4] length (w/out the header)
	if msg.Dirty && msg.Type != KEEPALIVE {
		dst = append(dst, `-1`...)
	} else {
		dst = strconv.AppendUint(dst, uint64(len(msg.Data)), 10)
	}

	// [5] data (or upper layer)
	dst = append(dst, ',')
	switch msg.Upper {
	case OPEN:
		dst = msg.Open.ToJSON(dst)
	case UPDATE:
		dst = msg.Update.ToJSON(dst)
	case KEEPALIVE:
		dst = append(dst, json.Null...)
	case NOTIFY:
		dst = append(dst, `"`...)
		dst = append(dst, msg.Data[2:]...) // FIXME
		dst = append(dst, `"`...)
	default:
		dst = json.Hex(dst, msg.Data)
	}

	// [6] value TODO: json serialize
	dst = append(dst, ',')
	if msg.Value != nil {
		dst = msg.Value.ToJSON(dst)
	} else {
		dst = append(dst, `null`...)
	}

	dst = append(dst, ']')
	return dst
}

// FromJSON reads msg JSON representation from src
func (msg *Msg) FromJSON(src []byte) (reterr error) {
	return json.ArrayEach(src, func(key int, val []byte, typ json.Type) (err error) {
		switch key {
		case 0: // time
			msg.Time, err = time.Parse(JSON_TIME, json.S(val))

		case 1: // seq number
			msg.Seq, err = strconv.ParseInt(json.S(val), 10, 64)

		case 2: // dst TODO: better
			if typ == json.STRING {
				msg.Dst, err = DstString(json.S(val))
			} else if typ == json.NUMBER {
				var v byte
				v, err = json.UnByte(val)
				msg.Dst = Dst(v)
			}

		case 3: // type TODO: better
			if typ == json.STRING {
				msg.Type, err = TypeString(json.S(val))
			} else if typ == json.NUMBER {
				var v byte
				v, err = json.UnByte(val)
				msg.Type = Type(v)
			}
			if msg.Type != INVALID {
				msg.SetUp(msg.Type)
			}

		case 5: // upper layer
			if typ == json.STRING {
				msg.buf, err = json.UnHex(val, msg.buf[:0])
				msg.Data = msg.buf
				msg.ref = false
				msg.Upper = INVALID
			} else {
				switch msg.Type {
				case OPEN:
					err = msg.Open.FromJSON(val)
				case UPDATE:
					err = msg.Update.FromJSON(val)
				default:
					err = ErrTODO // TODO
				}
			}

		case 6: // value
			if msg.Value != nil && typ != json.NULL {
				err = msg.Value.FromJSON(val)
			}
		}
		return err
	})
}
