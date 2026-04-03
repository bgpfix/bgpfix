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
		// NB: VPN nexthop = RD(8) + global(16) + RD(8) + link-local(16)
		ok = true
		addr = netip.AddrFrom16([16]byte(buf[8:24]))
		ll = netip.AddrFrom16([16]byte(buf[32:48]))
	}
	return
}
