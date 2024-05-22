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

// IsET returns true iff t is of Extended Timestamp type
func (t Type) IsET() bool {
	switch t {
	case BGP4MP_ET, OSPF3_ET, ISIS_ET:
		return true
	default:
		return false
	}
}

// IsBGP returns true iff t is of BGP4MP type
func (t Type) IsBGP4() bool {
	switch t {
	case BGP4MP, BGP4MP_ET:
		return true
	default:
		return false
	}
}

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
	mrt := new(Mrt)
	mrt.Bgp4.Init(mrt)
	return mrt
}

// Reset clears the message
func (mrt *Mrt) Reset() *Mrt {
	mrt.ref = false
	if cap(mrt.buf) < 1024*1024 {
		mrt.buf = mrt.buf[:0] // NB: re-use iff < 1MiB
	} else {
		mrt.buf = nil
	}

	mrt.Time = time.Time{}
	mrt.Type = 0
	mrt.Sub = 0
	mrt.Data = nil

	switch mrt.Upper {
	case BGP4MP, BGP4MP_ET:
		mrt.Bgp4.Reset()
	}
	mrt.Upper = INVALID

	return mrt
}

// Len returns total MRT message length, including header
func (mrt *Mrt) Len() int {
	switch {
	case mrt.Data == nil:
		return 0
	case mrt.Type.IsET():
		return len(mrt.Data) + HEADLEN + 4
	default:
		return len(mrt.Data) + HEADLEN
	}
}

// Use selects the upper layer of given type for active use.
// Drop mrt.Data, but does not touch the upper layer at all.
// Use Reset() on mrt or the selected layer if needed.
func (mrt *Mrt) Use(typ Type) *Mrt {
	mrt.Data = nil
	mrt.Type = typ
	mrt.Upper = typ
	return mrt
}

// CopyData copies the referenced data iff needed and makes mrt the owner
func (mrt *Mrt) CopyData() *Mrt {
	if !mrt.ref {
		return mrt // already owned
	} else {
		mrt.ref = false // tag as owned
	}

	// special case: nothing to do
	if mrt.Data == nil {
		return mrt
	}

	switch {
	case mrt.Data == nil: // no data
		return mrt
	case len(mrt.Data) == 0: // data empty
		if mrt.buf == nil {
			mrt.buf = make([]byte, 0)
		} else {
			mrt.buf = mrt.buf[:0]
		}
	default: // copy data
		mrt.buf = append(mrt.buf[:0], mrt.Data...)
	}

	mrt.Data = mrt.buf
	return mrt
}

// FromBytes parses the MRT message in raw. Does not copy.
// Returns the number of parsed bytes from raw.
func (mrt *Mrt) FromBytes(raw []byte) (off int, err error) {
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

	// write to mrt
	mrt.Time = time.Unix(int64(ts), 0).UTC()
	mrt.Type = Type(typ)
	mrt.Sub = Sub(sub)
	mrt.Data = nil
	mrt.ref = false
	off += l

	// extended timestamp?
	if mrt.Type.IsET() {
		if l < 4 {
			return off, ErrShort
		}
		us := msb.Uint32(data[0:4])
		mrt.Time = mrt.Time.Add(time.Microsecond * time.Duration(us))
		data = data[4:]
		l -= 4
	}

	// reference data
	mrt.ref = true
	mrt.Data = data[:l]

	// needs fresh Parse()
	mrt.Upper = INVALID

	// done!
	return off, nil
}

// Parse parses mrt.Data into the upper layer iff needed.
func (mrt *Mrt) Parse() error {
	if mrt.Upper != INVALID {
		return nil // assume already done
	} else if mrt.Data == nil {
		return ErrNoData
	}

	var err error
	switch mrt.Type {
	case BGP4MP, BGP4MP_ET:
		bgp4 := &mrt.Bgp4
		err = bgp4.Parse()
		if err != nil {
			break
		}
	default:
		err = ErrType
	}

	if err == nil {
		mrt.Upper = mrt.Type
	}

	return err
}

// Marshal marshals the upper layer to mrt.Data iff possible and needed.
func (mrt *Mrt) Marshal() error {
	if mrt.Data != nil {
		return nil // not needed
	}

	var err error
	switch mrt.Upper {
	case INVALID:
		return ErrNoUpper // not possible
	case BGP4MP, BGP4MP_ET:
		b := &mrt.Bgp4
		err = b.Marshal()
	default:
		err = ErrType
	}

	return err
}

// WriteTo writes raw MRT mrt.Data message to w, implementing io.WriterTo.
// Call mrt.Marshal() first if needed.
func (mrt *Mrt) WriteTo(w io.Writer) (n int64, err error) {
	// has data?
	if mrt.Data == nil {
		return 0, ErrNoData
	}

	// data length ok?
	l := mrt.Len()
	if l < HEADLEN || l > MAXLEN {
		return n, ErrLength
	}

	// write the timestamp
	time_us := mrt.Time.UnixMicro()
	k, err := msb.WriteUint32(w, uint32(time_us/1e9))
	n += int64(k)
	if err != nil {
		return n, err
	}

	// write type
	k, err = msb.WriteUint16(w, uint16(mrt.Type))
	n += int64(k)
	if err != nil {
		return n, err
	}

	// write subtype
	k, err = msb.WriteUint16(w, uint16(mrt.Sub))
	n += int64(k)
	if err != nil {
		return n, err
	}

	// write the length
	k, err = msb.WriteUint32(w, uint32(l-HEADLEN))
	n += int64(k)
	if err != nil {
		return n, err
	}

	// extended timestamp?
	if mrt.Type.IsET() {
		k, err = msb.WriteUint32(w, uint32(time_us%1e9))
		n += int64(k)
		if err != nil {
			return n, err
		}
	}

	// write data
	k, err = w.Write(mrt.Data)
	n += int64(k)
	if err != nil {
		return n, err
	}

	// done
	return n, nil
}
