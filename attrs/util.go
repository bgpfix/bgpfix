package attrs

import (
	"encoding/hex"
	"fmt"
	"net/netip"
	"strconv"
	"unsafe"

	"github.com/bgpfix/bgpfix/binary"
	jsp "github.com/buger/jsonparser"
)

var msb = binary.Msb

const hextable = "0123456789abcdef"

func jsonHex(dst []byte, src []byte) []byte {
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

func unjsonHex(dst []byte, src []byte) ([]byte, error) {
	src = unq(src)
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

func jsonByte(dst []byte, src byte) []byte {
	return strconv.AppendUint(dst, uint64(src), 10)
}

func unjsonByte(src []byte) (byte, error) {
	v, err := strconv.ParseUint(bs(src), 0, 8)
	return uint8(v), err
}

func jsonU32(dst []byte, src uint32) []byte {
	return strconv.AppendUint(dst, uint64(src), 10)
}

func unjsonU32(src []byte) (uint32, error) {
	v, err := strconv.ParseUint(bs(src), 0, 32)
	return uint32(v), err
}

func jsonBool(dst []byte, val bool) []byte {
	if val {
		return append(dst, `true`...)
	} else {
		return append(dst, `false`...)
	}
}

func jsonPrefixes(dst []byte, src []netip.Prefix) []byte {
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

func unjsonPrefixes(dst []netip.Prefix, src []byte) (out []netip.Prefix, reterr error) {
	defer func() {
		if r, ok := recover().(string); ok {
			reterr = fmt.Errorf("%w: %s", ErrValue, r)
		}
	}()

	out = dst
	jsp.ArrayEach(src, func(buf []byte, typ jsp.ValueType, _ int, _ error) {
		if typ != jsp.String {
			panic(bs(buf))
		}

		p, err := netip.ParsePrefix(bs(buf))
		if err != nil {
			panic(err.Error())
		}
		out = append(out, p)
	})
	return
}

// best-effort NH parser
func parseNH(buf []byte) (addr, ll netip.Addr, ok bool) {
	switch len(buf) {
	case 4:
		ok = true
		addr = netip.AddrFrom4([4]byte(buf))
	case 16, 24:
		ok = true
		addr = netip.AddrFrom16([16]byte(buf[:16]))
	case 32:
		ok = true
		addr = netip.AddrFrom16([16]byte(buf[0:16]))
		ll = netip.AddrFrom16([16]byte(buf[16:32]))
	case 48:
		ok = true
		addr = netip.AddrFrom16([16]byte(buf[0:16]))
		ll = netip.AddrFrom16([16]byte(buf[24:40]))
	}
	return
}

func appendPrefixes(dst []netip.Prefix, buf []byte, ipv6 bool) ([]netip.Prefix, error) {
	var tmp [16]byte
	var pfx netip.Prefix
	var err error
	for len(buf) > 0 {
		l := int(buf[0])
		buf = buf[1:]

		b := l / 8
		if l%8 != 0 {
			b++
		}
		if b > len(buf) {
			return dst, ErrLength
		}

		// copy what's defined
		copy(tmp[:], buf[:b])

		// zero the rest, try to parse
		if ipv6 {
			for i := b; i < 16; i++ {
				tmp[i] = 0
			}
			pfx, err = netip.AddrFrom16(tmp).Prefix(l)
		} else {
			for i := b; i < 4; i++ {
				tmp[i] = 0
			}
			pfx, err = netip.AddrFrom4([4]byte(tmp[:])).Prefix(l)
		}

		if err != nil {
			return dst, err
		}

		dst = append(dst, pfx)
		buf = buf[b:]
	}

	return dst, nil
}

func marshalPrefix(dst []byte, p netip.Prefix) []byte {
	l := p.Bits()
	b := l / 8
	if l%8 != 0 {
		b++
	}
	dst = append(dst, byte(l))
	return append(dst, p.Addr().AsSlice()[:b]...)
}

func marshalPrefixes(dst []byte, src []netip.Prefix) []byte {
	for _, p := range src {
		dst = marshalPrefix(dst, p)
	}
	return dst
}

// bs returns string from byte slice, in an unsafe way
func bs(buf []byte) string {
	return *(*string)(unsafe.Pointer(&buf))
}

// unq removes "double quotes" in buf, if present
func unq(buf []byte) []byte {
	if l := len(buf); l > 1 && buf[0] == '"' && buf[l-1] == '"' {
		return buf[1 : l-1]
	} else {
		return buf
	}
}

// bsu returns string from byte slice, unquoting if necessary
func bsu(buf []byte) string {
	if l := len(buf); l > 1 && buf[0] == '"' && buf[l-1] == '"' {
		buf = buf[1 : l-1]
	}
	return *(*string)(unsafe.Pointer(&buf))
}
