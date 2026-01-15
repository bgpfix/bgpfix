// Package binary provides binary read/write methods.
package binary

import (
	"encoding/binary"
	"io"
)

var Msb = msb{
	binary.BigEndian,
	binary.BigEndian,
}

type msb struct {
	binary.ByteOrder
	binary.AppendByteOrder
}

func (msb) WriteUint8(w io.Writer, v uint8) (n int, err error) {
	b := [...]byte{
		byte(v),
	}
	return w.Write(b[:])
}

func (msb) WriteUint16(w io.Writer, v uint16) (n int, err error) {
	b := [...]byte{
		byte(v >> 8),
		byte(v),
	}
	return w.Write(b[:])
}

func (msb) WriteUint32(w io.Writer, v uint32) (n int, err error) {
	b := [...]byte{
		byte(v >> 24),
		byte(v >> 16),
		byte(v >> 8),
		byte(v),
	}
	return w.Write(b[:])
}

func (msb) WriteUint64(w io.Writer, v uint64) (n int, err error) {
	b := [...]byte{
		byte(v >> 56),
		byte(v >> 48),
		byte(v >> 40),
		byte(v >> 32),
		byte(v >> 24),
		byte(v >> 16),
		byte(v >> 8),
		byte(v),
	}
	return w.Write(b[:])
}
