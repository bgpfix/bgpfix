package nlri

import (
	"net/netip"
	"strconv"
	"strings"

	"github.com/bgpfix/bgpfix/afi"
	"github.com/bgpfix/bgpfix/binary"
	"github.com/bgpfix/bgpfix/caps"
	"github.com/bgpfix/bgpfix/dir"
	"github.com/bgpfix/bgpfix/json"
)

var msb = binary.Msb

// NLRI is Network Layer Reachability Information (RFC4271),
// extended to support ADD_PATH (RFC7911).
type NLRI struct {
	netip.Prefix // the IP prefix

	Options Options // controls optional features
	Val     uint32  // additional NLRI value, eg. the ADD_PATH Path Identifier
}

type Options = byte

const (
	_           Options = iota
	OPT_VALUE           // Val holds some arbitrary value (user-controlled)
	OPT_ADDPATH         // Val holds ADD_PATH
)

// FromPrefix returns prefix p wrapped in NLRI
func FromPrefix(p netip.Prefix) NLRI {
	return NLRI{Prefix: p}
}

// FindParent returns the first index i into parents
// where parents[i] fully covers p, or -1 if not found.
func (p *NLRI) FindParent(parents []NLRI) int {
	addr, bits := p.Addr(), p.Bits()

	for i := range parents {
		p2 := &parents[i]
		switch bits2 := p2.Bits(); {
		case bits2 < bits:
			if p2.Overlaps(p.Prefix) {
				return i
			}
		case bits2 > bits:
			continue // p2 is smaller, no way its a parent
		default:
			if p2.Addr().Compare(addr) == 0 {
				return i
			}
		}
	}

	return -1
}

// ToJSON appends JSON representation of prefixes in src to dst
func ToJSON(dst []byte, src []NLRI) []byte {
	dst = append(dst, '[')
	for i := range src {
		p := &src[i]
		if i > 0 {
			dst = append(dst, ',')
		}
		if p.Options == OPT_ADDPATH {
			dst = append(dst, `"#`...)
			dst = json.Uint32(dst, p.Val)
			dst = append(dst, '#')
		} else {
			dst = append(dst, '"')
		}
		dst = p.Prefix.AppendTo(dst)
		dst = append(dst, '"')
	}
	return append(dst, ']')
}

// FromJSON parses JSON representation of prefixes in src into dst
func FromJSON(src []byte, dst []NLRI) ([]NLRI, error) {
	err := json.ArrayEach(src, func(key int, buf []byte, typ json.Type) error {
		var (
			nlri NLRI
			err  error
			s    = json.S(buf)
		)

		if len(s) == 0 {
			return json.ErrValue
		}

		// starts with #? treat as add-path path identifier
		if s[0] == '#' {
			before, after, found := strings.Cut(s[1:], "#")
			if !found || len(before) == 0 || len(after) == 0 {
				return json.ErrValue
			}
			val, err := strconv.ParseUint(before, 10, 32)
			if err != nil {
				return err
			}
			nlri.Options = OPT_ADDPATH
			nlri.Val = uint32(val)
			s = after
		}

		nlri.Prefix, err = netip.ParsePrefix(s)
		if err != nil {
			return err
		}

		dst = append(dst, nlri)
		return nil
	})
	return dst, err
}

// Unmarshal unmarshals src into prefix p
func (p *NLRI) Unmarshal(src []byte, ipv6, addpath bool) (n int, err error) {
	// reset options, just in case
	p.Options = 0

	// parse ADD_PATH Path Identifier?
	if addpath {
		if len(src) < 5 {
			return n, ErrLength
		}
		p.Options = OPT_ADDPATH
		p.Val = msb.Uint32(src[0:4])
		src = src[4:]
		n += 4
	}

	// prefix length in bits
	l := int(src[0])
	src = src[1:]
	n++
	if l > 128 || (!ipv6 && l > 32) {
		return n, ErrValue
	}

	// bit length -> bytes
	b := l / 8
	if l%8 != 0 {
		b++
	}
	if len(src) < b {
		return n, ErrLength
	}

	// copy what's defined, try to parse
	var tmp [16]byte
	n += copy(tmp[:], src[:b])
	if ipv6 {
		p.Prefix, err = netip.AddrFrom16(tmp).Prefix(l)
	} else {
		p.Prefix, err = netip.AddrFrom4([4]byte(tmp[:])).Prefix(l)
	}
	return n, err
}

// Unmarshal unmarshals IP prefixes from src into dst
func Unmarshal(dst []NLRI, src []byte, as afi.AS, cps caps.Caps, dir dir.Dir) ([]NLRI, error) {
	var (
		ipv6    = as.IsIPv6()
		addpath = cps.AddPathEnabled(as, dir)
	)

	for len(src) > 0 {
		l := len(dst)
		if cap(dst) > l {
			dst = dst[:l+1]
		} else {
			dst = append(dst, NLRI{})
		}
		p := &dst[l]

		n, err := p.Unmarshal(src, ipv6, addpath)
		if err != nil {
			return dst, ErrLength
		}

		src = src[n:]
	}

	return dst, nil
}

// Marshal marshals prefix p to dst
func (p *NLRI) Marshal(dst []byte, addpath bool) []byte {
	if addpath {
		if p.Options == OPT_ADDPATH {
			dst = msb.AppendUint32(dst, p.Val)
		} else {
			dst = msb.AppendUint32(dst, 0)
		}
	}

	l := p.Bits()
	b := l / 8
	if l%8 != 0 {
		b++
	}
	dst = append(dst, byte(l))

	return append(dst, p.Addr().AsSlice()[:b]...)
}

// Marshal marshals prefixes in src to dst
func Marshal(dst []byte, src []NLRI, as afi.AS, cps caps.Caps, dir dir.Dir) []byte {
	var (
		ipv6    = as.IsIPv6()
		addpath = cps.AddPathEnabled(as, dir)
	)
	for _, p := range src {
		if p.Addr().Is6() == ipv6 {
			dst = p.Marshal(dst, addpath)
		}
	}
	return dst
}
