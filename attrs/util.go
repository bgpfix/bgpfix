package attrs

import (
	"net/netip"
)

// ParseNH is best-effort parser for Next Hop value in buf
func ParseNH(buf []byte) (addr, ll netip.Addr, ok bool) {
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

// ReadPrefixes reads IP prefixes from buf into dst
func ReadPrefixes(dst []netip.Prefix, buf []byte, ipv6 bool) ([]netip.Prefix, error) {
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

// WritePrefix writes prefix p to dst
func WritePrefix(dst []byte, p netip.Prefix) []byte {
	l := p.Bits()
	b := l / 8
	if l%8 != 0 {
		b++
	}
	dst = append(dst, byte(l))
	return append(dst, p.Addr().AsSlice()[:b]...)
}

// WritePrefixes writes prefixes in src to dst
func WritePrefixes(dst []byte, src []netip.Prefix) []byte {
	for _, p := range src {
		dst = WritePrefix(dst, p)
	}
	return dst
}
