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

	ref bool   // true iff Data references memory we don't own
	buf []byte // internal buffer

	// optional metadata

	Dir  Dir       // message destination
	Seq  int64     // sequence number
	Time time.Time // message timestamp

	// raw contents

	Type Type   // message type
	Data []byte // message data (referenced or owned), can be nil

	// upper layer

	Upper  Type   // which of the upper layers is valid?
	Open   Open   // BGP OPEN message
	Update Update // BGP UPDATE message

	// for optional use beyond this pkg, eg. to store pipe.Context

	Value Value // NB: not affected by Reset()

	// JSON support

	json []byte // JSON representation (own memory), can be nil
}

// Value represents an optional, arbitrary value attached to a message
type Value interface {
	// ToJSON appends JSON representation of the value to dst
	ToJSON(dst []byte) []byte

	// FromJSON reads from JSON representation in src
	FromJSON(src []byte) error
}

// BGP message direction
type Dir byte

//go:generate go run github.com/dmarkham/enumer -type Dir -trimprefix DIR_
const (
	DIR_LR Dir = 0 // no particular direction (ie. both L and R)
	DIR_L  Dir = 1 // L direction: "left" or "local"
	DIR_R  Dir = 2 // R direction: "right" or "remote"
)

// Flip returns the opposite direction
func (d Dir) Flip() Dir {
	switch d {
	case DIR_L:
		return DIR_R
	case DIR_R:
		return DIR_L
	default:
		return 0
	}
}

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

	// https://datatracker.ietf.org/doc/html/rfc4271#autoid-9
	BgpMarker = []byte{
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
	msg.Dir = 0
	msg.Seq = 0
	msg.Time = time.Time{}
	msg.Type = 0

	msg.Data = nil
	msg.ref = false
	if cap(msg.buf) < 1024*1024 {
		msg.buf = msg.buf[:0] // NB: re-use iff < 1MiB
	} else {
		msg.buf = nil
	}

	switch msg.Upper {
	case OPEN:
		msg.Open.Reset()
	case UPDATE:
		msg.Update.Reset()
	}
	msg.Upper = INVALID

	if cap(msg.json) < 1024*1024 {
		msg.json = msg.json[:0] // NB: re-use iff < 1MiB
	} else {
		msg.json = nil
	}

	return msg
}

// Length returns total BGP message length, including the header.
// Call msg.Marshal() first if needed. Returns 0 on error.
func (msg *Msg) Length() int {
	if msg.Data == nil {
		return 0
	} else {
		return len(msg.Data) + HEADLEN
	}
}

// Use selects the upper layer of given type for active use.
// Calls msg.Modified(), but does not reset the selected upper layer.
// Use Reset() on msg or the selected layer if needed.
func (msg *Msg) Use(typ Type) *Msg {
	msg.Type = typ
	msg.Upper = typ
	msg.Modified()
	return msg
}

// Modified ditches msg.Data and its internal JSON representation,
// making the upper layer the only source of information about msg.
//
// Modified must be called when the upper layer is modified, to signal that
// both msg.Data and JSON representation must be regenerated when needed.
func (msg *Msg) Modified() {
	msg.Data = nil
	msg.json = msg.json[:0]
}

// CopyData makes msg the owner of msg.Data, copying referenced external data iff needed.
func (msg *Msg) CopyData() *Msg {
	if !msg.ref {
		return msg // already owned
	} else {
		msg.ref = false // tag as owned
	}

	switch {
	case msg.Data == nil: // no data
		return msg
	case len(msg.Data) == 0: // data empty
		if msg.buf == nil {
			msg.buf = make([]byte, 0)
		} else {
			msg.buf = msg.buf[:0]
		}
	default: // copy data
		msg.buf = append(msg.buf[:0], msg.Data...)
	}

	msg.Data = msg.buf
	return msg
}

// FromBytes reads one BGP message from buf, referencing buf data inside msg.Data.
// If needed, call CopyData(), DropData() or Reset() later to remove the reference.
// Returns the number of bytes read from buf, which can be less than len(buf).
func (msg *Msg) FromBytes(buf []byte) (off int, err error) {
	// enough data for marker + length + type?
	if len(buf) < HEADLEN {
		return off, io.ErrUnexpectedEOF
	}
	data := buf

	// find marker
	if !bytes.HasPrefix(data, BgpMarker) {
		return off, ErrMarker
	}
	off = len(BgpMarker)
	data = buf[off:]

	// read type and length
	l := int(msb.Uint16(data[:2]))
	msg.Type = Type(data[2])
	off += 3
	data = buf[off:]

	// check length
	dlen := l - HEADLEN
	if dlen < 0 {
		return off, ErrLength
	} else if dlen > len(data) {
		return off, io.ErrUnexpectedEOF
	}

	// reference data
	msg.ref = true
	msg.Data = data[:dlen]

	// needs fresh Parse() and GetJSON() results
	msg.Upper = INVALID
	msg.json = msg.json[:0]

	// done!
	return off + dlen, nil
}

// Parse parses msg.Data into the upper layer iff needed.
// Capabilities in caps can infuence the upper layer decoders.
// Does not reference data in msg.Data.
func (msg *Msg) Parse(cps caps.Caps) error {
	if msg.Upper != INVALID {
		return nil // assume already done
	} else if msg.Data == nil {
		return ErrNoData
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
		err = u.ParseAttrs(cps)
	case KEEPALIVE:
		if len(msg.Data) != 0 {
			err = ErrLength
		}
	case NOTIFY, REFRESH:
		// err = ErrTODO // TODO
	default:
		err = ErrType
	}

	if err == nil {
		msg.Upper = msg.Type
		msg.json = msg.json[:0]
	}

	return err
}

// Marshal marshals the upper layer to msg.Data iff possible and needed.
// caps can influence the upper layer encoders.
func (msg *Msg) Marshal(cps caps.Caps) error {
	if msg.Data != nil {
		return nil // not needed
	}

	var err error
	switch msg.Upper {
	case INVALID:
		return ErrNoUpper // not possible
	case OPEN:
		o := &msg.Open
		err = o.MarshalCaps()
		if err != nil {
			break
		}
		err = o.Marshal()
	case UPDATE:
		u := &msg.Update
		err = u.MarshalAttrs(cps)
		if err != nil {
			break
		}
		err = u.Marshal(cps)
	case KEEPALIVE:
		if msg.buf == nil {
			msg.buf = make([]byte, 0)
		} else {
			msg.buf = msg.buf[:0]
		}
		msg.Type = KEEPALIVE
		msg.Data = msg.buf
		msg.ref = false
	default:
		err = ErrType
	}

	return err
}

// WriteTo writes raw BGP msg.Data to w, implementing io.WriterTo.
// Call msg.Marshal() first if needed.
func (msg *Msg) WriteTo(w io.Writer) (n int64, err error) {
	var m int

	// has data?
	if msg.Data == nil {
		return 0, ErrNoData
	}

	// data length ok?
	l := msg.Length()
	if l < HEADLEN || l > MAXLEN {
		return 0, ErrLength
	}

	// write the marker
	m, err = w.Write(BgpMarker)
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

	// write data
	m, err = w.Write(msg.Data)
	if err != nil {
		return
	}
	n += int64(m)

	// done
	return
}

// String dumps msg to JSON string, without the trailing newline
func (msg *Msg) String() string {
	j := msg.GetJSON()
	return string(j[:len(j)-1])
}

// GetJSON returns JSON representation of msg + "\n" directly from an internal buffer.
// The result is always non-nil and non-empty. Copy the result if you need to keep it.
func (msg *Msg) GetJSON() []byte {
	// still good?
	if msg.Upper != INVALID && len(msg.json) > 0 {
		return msg.json
	}

	// nope, start from scratch
	dst := append(msg.json[:0], `["`...)

	// [0] direction
	dst = append(dst, msg.Dir.String()...) // TODO: or number
	dst = append(dst, `",`...)

	// [1] sequence number (for dir)
	dst = strconv.AppendInt(dst, msg.Seq, 10)
	dst = append(dst, `,"`...)

	// [2] time
	dst = append(dst, msg.Time.Format(JSON_TIME)...)
	dst = append(dst, `",`...)

	// [3] length (w/out the header)
	if msg.Data == nil && msg.Type != KEEPALIVE {
		dst = append(dst, `-1`...)
	} else {
		dst = strconv.AppendUint(dst, uint64(len(msg.Data)), 10)
	}

	// [4] type
	dst = append(dst, `,"`...)
	dst = append(dst, msg.Type.String()...) // TODO: or number
	dst = append(dst, `",`...)

	// [5] data (or upper layer)
	switch msg.Upper {
	case OPEN:
		dst = msg.Open.ToJSON(dst)
	case UPDATE:
		dst = msg.Update.ToJSON(dst)
	case KEEPALIVE:
		dst = append(dst, json.Null...)
	case NOTIFY:
		dst = append(dst, '"')
		dst = json.Ascii(dst, msg.Data[2:]) // FIXME
		dst = append(dst, '"')
	default:
		dst = json.Hex(dst, msg.Data)
	}

	// [6] value
	dst = append(dst, ',')
	if msg.Value != nil {
		dst = msg.Value.ToJSON(dst)
	} else {
		dst = append(dst, `null`...)
	}

	// done!
	msg.json = append(dst, "]\n"...)
	return msg.json
}

// ToJSON appends JSON representation of msg + "\n" to dst (may be nil to allocate)
func (msg *Msg) ToJSON(dst []byte) []byte {
	return append(dst[:0], msg.GetJSON()...)
}

// FromJSON reads msg JSON representation from src into Upper
func (msg *Msg) FromJSON(src []byte) (reterr error) {
	// internal json still valid?
	if l := len(msg.json) - 1; l > 0 && msg.Upper != INVALID {
		src = bytes.TrimSpace(src)
		if len(src) == l && string(src) == string(msg.json[:l]) {
			return nil // yay! we're done
		}
	}

	msg.Modified() // will modify Upper
	return json.ArrayEach(src, func(key int, val []byte, typ json.Type) (err error) {
		switch key {
		case 0: // dst TODO: better
			if typ == json.STRING {
				msg.Dir, err = DirString(json.S(val))
			} else if typ == json.NUMBER {
				var v byte
				v, err = json.UnByte(val)
				msg.Dir = Dir(v)
			}

		case 1: // seq number
			msg.Seq, err = strconv.ParseInt(json.S(val), 10, 64)

		case 2: // time
			if typ == json.STRING && len(val) > 0 {
				msg.Time, err = time.Parse(JSON_TIME, json.S(val))
			}

		// NB: ignore [3] = wire length

		case 4: // type TODO: better
			if typ == json.STRING {
				msg.Type, err = TypeString(json.S(val))
			} else if typ == json.NUMBER {
				var v byte
				v, err = json.UnByte(val)
				msg.Type = Type(v)
			}
			if msg.Type != INVALID {
				msg.Use(msg.Type)
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
			if msg.Value != nil && len(val) > 0 {
				err = msg.Value.FromJSON(val)
			}
		}
		return err
	})
}
