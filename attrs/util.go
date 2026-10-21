package attrs

import (
	"bytes"
	"net/netip"
)

// cut2 splits src at ':' into exactly 2 parts, without allocating
func cut2(src []byte) (a, b []byte, ok bool) {
	a, b, ok = bytes.Cut(src, []byte{':'})
	return a, b, ok && bytes.IndexByte(b, ':') < 0
}

// cut3 splits src at ':' into exactly 3 parts, without allocating
func cut3(src []byte) (a, b, c []byte, ok bool) {
	a, rest, ok := bytes.Cut(src, []byte{':'})
	if !ok {
		return
	}
	b, c, ok = cut2(rest)
	return
}

// ParseNH is best-effort parser for Next Hop value in buf
func ParseNH(buf []byte) (addr, ll netip.Addr, ok bool) {
	switch len(buf) {
	case 4:
		ok = true
		addr = netip.AddrFrom4([4]byte(buf))
	case 16:
		ok = true
		addr = netip.AddrFrom16([16]byte(buf[:16]))
	case 24:
		// NB: VPN nexthop = RD(8) + global(16), per RFC 4659
		ok = true
		addr = netip.AddrFrom16([16]byte(buf[8:24]))
	case 32:
		ok = true
		addr = netip.AddrFrom16([16]byte(buf[0:16]))
		ll = netip.AddrFrom16([16]byte(buf[16:32]))
	case 48:
		// NB: VPN nexthop = RD(8) + global(16) + RD(8) + link-local(16)
		ok = true
		addr = netip.AddrFrom16([16]byte(buf[8:24]))
		ll = netip.AddrFrom16([16]byte(buf[32:48]))
	}
	return
}
