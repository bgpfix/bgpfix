package mrt

import (
	"io"
	"math"
	"time"

	"github.com/bgpfix/bgpfix/binary"
)

// Msg represents a bare-bones MRT message (rfc6396/2).
type Msg struct {
	// internal
	ref bool   // true iff Data is a reference to borrowed memory
	buf []byte // internal buffer

	Seq  uint64    `json:"seq,omitempty"` // sequence number (optional)
	Time time.Time `json:"time"`          // message timestamp
	Type MsgType   `json:"typ"`           // message type
	Sub  MsgSub    `json:"sub"`           // message subtype
	Data []byte    `json:"raw,omitempty"` // message data (referenced or owned), can be nil
}

// MRT message type and subtype
type MsgType = uint16
type MsgSub = uint16

// from https://www.iana.org/assignments/mrt/mrt.xhtml
const (
	TYPE_UNSPECIFIED MsgType = 0

	TYPE_OSPF2    MsgType = 11
	TYPE_OSPF3    MsgType = 48
	TYPE_OSPF3_ET MsgType = 49

	TYPE_TABLE_DUMP  MsgType = 12
	TYPE_TABLE_DUMP2 MsgType = 13

	TYPE_BGP4MP    MsgType = 16
	TYPE_BGP4MP_ET MsgType = 17

	TYPE_ISIS    MsgType = 32
	TYPE_ISIS_ET MsgType = 33
)

// Address Families, in the context of MRT headers
const (
	AFI_IPv4 = 1
	AFI_IPv6 = 2
)

const (
	// MRT header length
	MSG_HEADLEN = 12 // = timestamp(4) + type(2) + subtype (2) + length (4)

	// MRT maximum data length
	MSG_MAXLEN = math.MaxUint32
)

var (
	msb = binary.Msb
)

// NewMsg returns new empty message
func NewMsg() *Msg {
	return new(Msg)
}

// NewMsgType returns new message with given params.
func NewMsgType(ts time.Time, typ MsgType, sub MsgSub, data []byte) (*Msg, error) {
	if len(data) > MSG_MAXLEN {
		return nil, ErrLong
	}
	return &Msg{
		ref:  data != nil,
		Time: ts,
		Type: typ,
		Sub:  sub,
		Data: data,
	}, nil
}

// Length returns total MRT message length, including header
func (msg *Msg) Length() int {
	return len(msg.Data) + MSG_HEADLEN
}

// SetData updates the data to reference given value
func (msg *Msg) SetData(data []byte) error {
	if len(data) > MSG_MAXLEN {
		return ErrLong
	}

	msg.ref = data != nil
	msg.Data = data
	return nil
}

// Own tags msg as the owner of referenced data. Does not copy the data.
func (msg *Msg) Own() {
	if !msg.ref {
		return // already owned
	}

	// tag as owned
	msg.ref = false
}

// Disown tags msg as not the owner of data.
func (msg *Msg) Disown() {
	if msg.ref {
		return // already disowned
	}

	// tag as reference
	msg.ref = true
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

// Clone writes a copy to dst, referencing data from msg. Drops raw message Data.
func (msg *Msg) Clone(dst *Msg) *Msg {
	if msg == nil {
		return nil
	} else if dst == nil {
		dst = new(Msg)
	}
	dst.ref = false
	dst.buf = dst.buf[:0]
	dst.Seq = msg.Seq
	dst.Time = msg.Time
	dst.Type = msg.Type
	dst.Data = nil
	return dst
}

// Reset clears the message
func (msg *Msg) Reset() {
	msg.ref = false
	// NB: re-use msg.buf if < 1MiB
	if cap(msg.buf) > 1024*1024 {
		msg.buf = nil
	} else {
		msg.buf = msg.buf[:0]
	}
	msg.Seq = 0
	msg.Type = 0
	msg.Data = nil
}

// Parse parses the MRT message in raw. Does not copy.
// Returns the number of parsed bytes from raw.
func (msg *Msg) Parse(raw []byte) (off int, err error) {
	// enough bytes for header?
	if len(raw) < MSG_HEADLEN {
		return off, io.ErrUnexpectedEOF
	}
	data := raw

	// read
	ts := msb.Uint32(data[0:4])
	typ := msb.Uint16(data[4:6])
	sub := msb.Uint16(data[6:8])
	l := int(msb.Uint32(data[8:12]))
	off += 12
	data = raw[off:]

	// enough bytes for data?
	if len(data) < l {
		return off, io.ErrUnexpectedEOF
	}

	// write msg
	msg.Time = time.Unix(int64(ts), 0).UTC()
	msg.Type = MsgType(typ)
	msg.Sub = MsgSub(sub)
	msg.Data = nil
	msg.ref = false
	off += l

	// extended timestamp?
	switch msg.Type {
	case TYPE_BGP4MP_ET, TYPE_ISIS_ET, TYPE_OSPF3_ET:
		if l < 4 {
			return off, ErrShort
		}
		us := msb.Uint32(data[0:4])
		msg.Time = msg.Time.Add(time.Microsecond * time.Duration(us))
		data = data[4:]
		l -= 4
	}

	// write data
	if l > 0 {
		msg.ref = true
		msg.Data = data[:l]
	} else {
		msg.ref = false
		msg.Data = nil
	}

	// done!
	return off, nil
}

// WriteTo writes the MRT message to w, implementing io.WriterTo
func (msg *Msg) WriteTo(w io.Writer) (n int64, err error) {
	var m int

	// data length ok?
	if len(msg.Data) > MSG_MAXLEN {
		return 0, ErrLength
	}

	// write the timestamp
	m, err = msb.WriteUint32(w, uint32(msg.Time.Unix()))
	if err != nil {
		return
	}
	n += int64(m)

	// write type
	m, err = msb.WriteUint16(w, msg.Type)
	if err != nil {
		return
	}
	n += int64(m)

	// write subtype
	m, err = msb.WriteUint16(w, msg.Sub)
	if err != nil {
		return
	}
	n += int64(m)

	// write the length
	m, err = msb.WriteUint32(w, uint32(len(msg.Data)))
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
