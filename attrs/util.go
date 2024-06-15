package attrs

import (
	"net/netip"

	"github.com/bgpfix/bgpfix/af"
	"github.com/bgpfix/bgpfix/caps"
	"github.com/bgpfix/bgpfix/nlri"
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

// ReadPrefixes reads IP prefixes from src into dst
func ReadPrefixes(dst []nlri.NLRI, src []byte, as af.AF, cps caps.Caps) (result []nlri.NLRI, err error) {
	var (
		tmp        [16]byte
		ipv6       = as.IsAfi(af.AFI_IPV6)
		addpath    = cps.AddPathReceive(as)
		besteffort = cps.BestEffortGet(caps.CAP_ADDPATH)
	)

retry:
	buf := src
	for len(buf) > 0 {
		var p nlri.NLRI

		// parse ADD_PATH Path Identifier?
		if addpath {
			if len(buf) < 5 {
				err = ErrLength
				break
			}
			id := msb.Uint32(buf[0:4])
			p.PathId = &id
			buf = buf[4:]
		}

		// prefix length in bits
		l := int(buf[0])
		buf = buf[1:]

		b := l / 8
		if l%8 != 0 {
			b++
		}
		if b > len(buf) {
			err = ErrLength
			break
		}

		// copy what's defined
		copy(tmp[:], buf[:b])

		// zero the rest, try to parse
		if ipv6 {
			for i := b; i < 16; i++ {
				tmp[i] = 0
			}
			p.Prefix, err = netip.AddrFrom16(tmp).Prefix(l)
		} else {
			for i := b; i < 4; i++ {
				tmp[i] = 0
			}
			p.Prefix, err = netip.AddrFrom4([4]byte(tmp[:])).Prefix(l)
		}
		if err != nil {
			break
		}

		// take it
		dst = append(dst, p)
		buf = buf[b:]
	}

	// parse error?
	if err != nil {
		// no ADD_PATH but we can best-effort retry?
		if !addpath && besteffort > 0 {
			err = nil
			addpath = true
			besteffort = 3
			goto retry
		}

		// nope, it's dead end
		if besteffort > 0 {
			cps.BestEffortSet(caps.CAP_ADDPATH, -1) // tried and didn't work
		}
		return dst, err
	}

	// ADD_PATH success after our best-effort retry?
	if addpath && besteffort == 3 {
		cps.BestEffortSet(caps.CAP_ADDPATH, 2) // tried and worked
	}

	return dst, err
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
func WritePrefixes(dst []byte, src []nlri.NLRI, as af.AF, cps caps.Caps) []byte {
	var (
		ipv6    = as.IsAfi(af.AFI_IPV6)
		addpath = cps.AddPathSend(as)
	)
	for _, p := range src {
		if p.Addr().Is6() != ipv6 {
			continue
		}
		if addpath {
			if p.PathId != nil {
				dst = msb.AppendUint32(dst, *p.PathId)
			} else {
				dst = msb.AppendUint32(dst, 0)
			}
		}
		dst = WritePrefix(dst, p.Prefix)
	}
	return dst
}
