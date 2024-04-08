// Package mrt supports BGP data in MRT format (RFC6396)
package mrt

import (
	"io"
	"math"
	"time"

	"github.com/bgpfix/bgpfix/binary"
)

// Mrt represents a bare-bones MRT message (rfc6396/2).
type Mrt struct {
	// internal
	ref bool   // true iff Data is a reference to borrowed memory
	buf []byte // internal buffer

	Time time.Time // message timestamp
	Type Type      // message type
	Sub  Sub       // message subtype
	Data []byte    // message data (referenced or owned), can be nil

	Upper Type // which of the upper layers is valid?
	Bgp4  Bgp4 // BGP4MP or BGP4MP_ET
}

// MRT message type, see https://www.iana.org/assignments/mrt/mrt.xhtml
type Type uint16

//go:generate go run github.com/dmarkham/enumer -type Type
const (
	INVALID Type = 0

	OSPF2    Type = 11
	OSPF3    Type = 48
	OSPF3_ET Type = 49

	TABLE_DUMP  Type = 12
	TABLE_DUMP2 Type = 13

	BGP4MP    Type = 16
	BGP4MP_ET Type = 17

	ISIS    Type = 32
	ISIS_ET Type = 33
)

// MRT message subtype, see https://www.iana.org/assignments/mrt/mrt.xhtml
type Sub uint16

//go:generate go run github.com/dmarkham/enumer -type Sub

const (
	// MRT header length
	HEADLEN = 12 // = timestamp(4) + type(2) + subtype (2) + length (4)

	// MRT maximum data length
	MAXLEN = math.MaxUint32
)

var (
	msb = binary.Msb
)

// NewMrt returns new empty message
func NewMrt() *Mrt {
	m := new(Mrt)
	m.Bgp4.Init(m)
	return m
}

// Reset clears the message
func (m *Mrt) Reset() *Mrt {
	m.ref = false
	if cap(m.buf) < 1024*1024 {
		m.buf = m.buf[:0] // NB: re-use iff < 1MiB
	} else {
		m.buf = nil
	}

	m.Time = time.Time{}
	m.Type = 0
	m.Sub = 0
	m.Data = nil

	switch m.Upper {
	case BGP4MP, BGP4MP_ET:
		m.Bgp4.Reset()
	}
	m.Upper = INVALID

	return m
}

// Length returns total MRT message length, including header
func (m *Mrt) Length() int {
	if m.Data == nil {
		return 0
	} else {
		return len(m.Data) + HEADLEN
	}
}

// CopyData copies the referenced data iff needed and makes msg the owner
func (m *Mrt) CopyData() *Mrt {
	if !m.ref {
		return m // already owned
	} else {
		m.ref = false // tag as owned
	}

	// special case: nothing to do
	if m.Data == nil {
		return m
	}

	switch {
	case m.Data == nil: // no data
		return m
	case len(m.Data) == 0: // data empty
		if m.buf == nil {
			m.buf = make([]byte, 0)
		} else {
			m.buf = m.buf[:0]
		}
	default: // copy data
		m.buf = append(m.buf[:0], m.Data...)
	}

	m.Data = m.buf
	return m
}

// FromBytes parses the MRT message in raw. Does not copy.
// Returns the number of parsed bytes from raw.
func (m *Mrt) FromBytes(raw []byte) (off int, err error) {
	// enough bytes for header?
	if len(raw) < HEADLEN {
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

	// write to m
	m.Time = time.Unix(int64(ts), 0).UTC()
	m.Type = Type(typ)
	m.Sub = Sub(sub)
	m.Data = nil
	m.ref = false
	off += l

	// extended timestamp?
	switch m.Type {
	case BGP4MP_ET, ISIS_ET, OSPF3_ET:
		if l < 4 {
			return off, ErrShort
		}
		us := msb.Uint32(data[0:4])
		m.Time = m.Time.Add(time.Microsecond * time.Duration(us))
		data = data[4:]
		l -= 4
	}

	// write data
	if l > 0 {
		m.ref = true
		m.Data = data[:l]
	} else {
		m.ref = false
		m.Data = nil
	}

	// done!
	return off, nil
}

// Parse parses m.Data into the upper layer iff needed.
func (m *Mrt) Parse() error {
	if m.Upper != INVALID {
		return nil // assume already done
	} else if m.Data == nil {
		return ErrNoData
	}

	var err error
	switch m.Type {
	case BGP4MP, BGP4MP_ET:
		bgp4 := &m.Bgp4
		err = bgp4.Parse()
		if err != nil {
			break
		}
	default:
		err = ErrType
	}

	if err == nil {
		m.Upper = m.Type
	}

	return err
}

// WriteTo writes the MRT message to w, implementing io.WriterTo
func (m *Mrt) WriteTo(w io.Writer) (n int64, err error) {
	// data length ok?
	if int64(len(m.Data)) > MAXLEN {
		return n, ErrLength
	}

	// write the timestamp
	k, err := msb.WriteUint32(w, uint32(m.Time.Unix()))
	n += int64(k)
	if err != nil {
		return n, err
	}

	// write type
	k, err = msb.WriteUint16(w, uint16(m.Type))
	n += int64(k)
	if err != nil {
		return n, err
	}

	// write subtype
	k, err = msb.WriteUint16(w, uint16(m.Sub))
	n += int64(k)
	if err != nil {
		return n, err
	}

	// write the length
	k, err = msb.WriteUint32(w, uint32(len(m.Data)))
	n += int64(k)
	if err != nil {
		return n, err
	}

	// write data?
	if len(m.Data) > 0 {
		k, err = w.Write(m.Data)
		n += int64(k)
		if err != nil {
			return n, err
		}
	}

	// done
	return n, nil
}
