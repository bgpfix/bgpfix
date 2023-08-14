// Package json provides JSON utilities
package json

import (
	"encoding/hex"
	"net/netip"
	"strconv"
	"unsafe"

	jsp "github.com/buger/jsonparser"
)

const hextable = "0123456789abcdef"

func Hex(dst []byte, src []byte) []byte {
	if src == nil {
		return append(dst, `null`...)
	} else if len(src) == 0 {
		return append(dst, `""`...)
	}

	dst = append(dst, `"0x`...)
	for _, v := range src {
		dst = append(dst, hextable[v>>4], hextable[v&0x0f])
	}
	return append(dst, '"')
}

func UnHex(dst []byte, src []byte) ([]byte, error) {
	src = Q(src)
	if len(src) < 2 {
		return dst, nil
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

func Byte(dst []byte, src byte) []byte {
	return strconv.AppendUint(dst, uint64(src), 10)
}

func UnByte(src []byte) (byte, error) {
	v, err := strconv.ParseUint(BS(src), 0, 8)
	return uint8(v), err
}

func U32(dst []byte, src uint32) []byte {
	return strconv.AppendUint(dst, uint64(src), 10)
}

func UnU32(src []byte) (uint32, error) {
	v, err := strconv.ParseUint(BS(src), 0, 32)
	return uint32(v), err
}

func Bool(dst []byte, val bool) []byte {
	if val {
		return append(dst, `true`...)
	} else {
		return append(dst, `false`...)
	}
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

func UnPrefixes(dst []netip.Prefix, src []byte) (out []netip.Prefix, reterr error) {
	defer func() {
		if r, ok := recover().(error); ok {
			reterr = r
		}
	}()

	out = dst
	jsp.ArrayEach(src, func(buf []byte, typ jsp.ValueType, _ int, _ error) {
		p, err := netip.ParsePrefix(BS(buf))
		if err != nil {
			panic(err)
		}
		out = append(out, p)
	})
	return
}

// BS returns string from byte slice, in an unsafe way
func BS(buf []byte) string {
	return *(*string)(unsafe.Pointer(&buf))
}

// Q removes "double quotes" in buf, if present
func Q(buf []byte) []byte {
	if l := len(buf); l > 1 && buf[0] == '"' && buf[l-1] == '"' {
		return buf[1 : l-1]
	} else {
		return buf
	}
}

// BSQ returns string from byte slice, unquoting if necessary
func BSQ(buf []byte) string {
	if l := len(buf); l > 1 && buf[0] == '"' && buf[l-1] == '"' {
		buf = buf[1 : l-1]
	}
	return *(*string)(unsafe.Pointer(&buf))
}
