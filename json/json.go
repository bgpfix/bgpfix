// Package json provides JSON utilities and wrappers around buger/jsonparser
package json

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"unsafe"

	jsp "github.com/buger/jsonparser"
)

const hextable = "0123456789abcdef"

type Type = jsp.ValueType

const (
	STRING = jsp.String
	NUMBER = jsp.Number
	OBJECT = jsp.Object
	ARRAY  = jsp.Array
	BOOL   = jsp.Boolean
	NULL   = jsp.Null
)

var (
	ErrValue = errors.New("invalid value")

	True  = []byte("true")
	False = []byte("false")
	Null  = []byte("null")
)

func Hex(dst []byte, src []byte) []byte {
	if src == nil {
		return append(dst, Null...)
	} else if len(src) == 0 {
		return append(dst, `""`...)
	}

	dst = append(dst, `"0x`...)
	for _, v := range src {
		dst = append(dst, hextable[v>>4], hextable[v&0x0f])
	}
	return append(dst, '"')
}

func UnHex(src []byte, dst []byte) ([]byte, error) {
	src = Q(src)
	if l := len(src); l == 0 {
		return dst, nil
	} else if l%2 != 0 {
		return dst, ErrValue
	} else if src[0] == '0' && src[1] == 'x' {
		src = src[2:]
	}
	bl := len(src) / 2
	if cap(dst) >= bl {
		dst = dst[:bl]
	} else {
		dst = make([]byte, bl)
	}
	_, err := hex.Decode(dst, src)
	return dst, err
}

func Int(dst []byte, src int) []byte {
	return strconv.AppendInt(dst, int64(src), 10)
}

func UnInt(src []byte) (int, error) {
	v, err := strconv.ParseInt(SQ(src), 0, 0)
	return int(v), err
}

func Byte(dst []byte, src byte) []byte {
	return strconv.AppendUint(dst, uint64(src), 10)
}

func UnByte(src []byte) (byte, error) {
	v, err := strconv.ParseUint(SQ(src), 0, 8)
	return uint8(v), err
}

func Uint16(dst []byte, src uint16) []byte {
	return strconv.AppendUint(dst, uint64(src), 10)
}

func UnUint16(src []byte) (uint16, error) {
	v, err := strconv.ParseUint(SQ(src), 0, 16)
	return uint16(v), err
}

func Uint32(dst []byte, src uint32) []byte {
	return strconv.AppendUint(dst, uint64(src), 10)
}

func UnUint32(src []byte) (uint32, error) {
	v, err := strconv.ParseUint(SQ(src), 0, 32)
	return uint32(v), err
}

func Bool(dst []byte, val bool) []byte {
	if val {
		return append(dst, True...)
	} else {
		return append(dst, False...)
	}
}

func UnBool(src []byte) (bool, error) {
	switch SQ(src) {
	case "true", "TRUE", "1":
		return true, nil
	case "false", "FALSE", "0":
		return false, nil
	default:
		return false, ErrValue
	}
}

func Addr(dst []byte, src netip.Addr) []byte {
	dst = append(dst, '"')
	dst = src.AppendTo(dst)
	return append(dst, '"')
}

func UnAddr(src []byte) (netip.Addr, error) {
	return netip.ParseAddr(SQ(src))
}

func Prefix(dst []byte, src netip.Prefix) []byte {
	dst = append(dst, '"')
	dst = src.AppendTo(dst)
	return append(dst, '"')
}

func UnPrefix(src []byte) (netip.Prefix, error) {
	return netip.ParsePrefix(SQ(src))
}

// Ascii appends ASCII characters from src to JSON string in dst
func Ascii(dst, src []byte) []byte {
	for _, c := range src {
		if c >= 0x20 && c <= 0x7e {
			dst = append(dst, c)
		} else {
			switch c {
			case '"', '\\':
				dst = append(dst, '\\', c)
			case '\r':
				dst = append(dst, '\\', 'r')
			case '\n':
				dst = append(dst, '\\', 'n')
			case '\t':
				dst = append(dst, '\\', 't')
			default:
				dst = append(dst, "\\u00"...)
				dst = append(dst, hextable[c>>4], hextable[c&0x0f])
			}
		}
	}
	return dst
}

func Prefixes(dst []byte, src []netip.Prefix) []byte {
	dst = append(dst, '[')
	for i := range src {
		if i > 0 {
			dst = append(dst, `,"`...)
		} else {
			dst = append(dst, '"')
		}
		dst = src[i].AppendTo(dst)
		dst = append(dst, '"')
	}
	return append(dst, ']')
}

func UnPrefixes(src []byte, dst []netip.Prefix) ([]netip.Prefix, error) {
	err := ArrayEach(src, func(key int, buf []byte, typ Type) error {
		p, err := netip.ParsePrefix(S(buf))
		if err != nil {
			return err
		}
		dst = append(dst, p)
		return nil
	})
	return dst, err
}

// S returns string from byte slice, in an unsafe way
func S(buf []byte) string {
	return unsafe.String(&buf[0], len(buf))
}

// B returns byte slice from string, in an unsafe way
func B(str string) []byte {
	return unsafe.Slice(unsafe.StringData(str), len(str))
}

// Q removes "double quotes" in buf, if present
func Q(buf []byte) []byte {
	if l := len(buf); l > 1 && buf[0] == '"' && buf[l-1] == '"' {
		return buf[1 : l-1]
	} else {
		return buf
	}
}

// SQ returns string from byte slice, unquoting if necessary
func SQ(buf []byte) string {
	if l := len(buf); l > 1 && buf[0] == '"' && buf[l-1] == '"' {
		buf = buf[1 : l-1]
	}
	return unsafe.String(&buf[0], len(buf))
}

// ArrayEach calls cb for each *non-nil* value in the src array.
// If the callback returns or panics with an error, ArrayEach immediately returns it.
func ArrayEach(src []byte, cb func(key int, val []byte, typ Type) error) (reterr error) {
	var key int

	// convert panics into returned error
	defer func() {
		switch v := recover().(type) {
		case nil:
			break
		case error:
			reterr = fmt.Errorf("[%d]: %w", key, v)
		case string:
			reterr = fmt.Errorf("[%d]: %s", key, v)
		default:
			reterr = fmt.Errorf("[%d]: %v", key, v)
		}
	}()

	// iterate
	key = -1
	_, reterr = jsp.ArrayEach(src, func(val []byte, typ Type, _ int, _ error) {
		// skip nulls
		key++
		if typ == NULL {
			return // skip
		}

		// call cb, may panic
		err := cb(key, val, typ)
		if err != nil {
			panic(err) // the only way to break from ArrayEach
		}
	})

	return
}

// ObjectEach calls cb for each non-null value in the src object.
// If the callback returns or panics with an error, ObjectEach immediately returns it.
func ObjectEach(src []byte, cb func(key string, val []byte, typ Type) error) (reterr error) {
	var panikey []byte

	// convert panics into returned error
	defer func() {
		switch v := recover().(type) {
		case nil:
			break
		case error:
			reterr = fmt.Errorf("[%s]: %w", panikey, v)
		case string:
			reterr = fmt.Errorf("[%s]: %s", panikey, v)
		default:
			reterr = fmt.Errorf("[%s]: %v", panikey, v)
		}
	}()

	return jsp.ObjectEach(src, func(key, val []byte, typ Type, _ int) error {
		// skip nulls
		panikey = key
		if typ == NULL {
			return nil // skip
		}

		// call cb, may panic
		err := cb(S(key), val, typ)
		if err != nil {
			panic(err) // will be caught
		}
		return nil
	})
}

// Get returns raw JSON value located at given key path, or nil if not found or error.
func Get(src []byte, path ...string) []byte {
	gval, gtyp, _, gerr := jsp.Get(src, path...)
	if gerr != nil || gtyp == NULL {
		return nil
	} else {
		return gval
	}
}

// GetBool returns true iff src JSON has a true value at given key path.
func GetBool(src []byte, path ...string) bool {
	gval, gtyp, _, gerr := jsp.Get(src, path...)
	if gerr != nil || gtyp == NULL {
		return false
	}
	switch SQ(gval) {
	case "true", "TRUE", "1":
		return true
	default:
		return false
	}
}
