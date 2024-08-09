// Package af implements AFI, SAFI, and combinations
package af

import (
	"strings"

	"github.com/bgpfix/bgpfix/binary"
	"github.com/bgpfix/bgpfix/json"
)

var msb = binary.Msb

// AF represents AFI+SAFI as afi(16) + 0(8) + safi(8)
type AF uint32

// common AFI + SAFI combinations
var (
	AF_IPV4_UNICAST   = NewAF(AFI_IPV4, SAFI_UNICAST)
	AF_IPV4_MULTICAST = NewAF(AFI_IPV4, SAFI_MULTICAST)
	AF_IPV6_UNICAST   = NewAF(AFI_IPV6, SAFI_UNICAST)
	AF_IPV6_MULTICAST = NewAF(AFI_IPV6, SAFI_MULTICAST)
)

// NewAF returns AF for given Afi and Safi
func NewAF(afi AFI, safi SAFI) AF {
	return AF(uint32(afi)<<16 | uint32(safi))
}

// NewAFBytes reads AF from wire representation in buf
func NewAFBytes(buf []byte) AF {
	if len(buf) == 4 {
		return AF(uint32(msb.Uint16(buf[0:2]))<<16 | uint32(buf[3]))
	} else if len(buf) == 3 {
		return AF(uint32(msb.Uint16(buf[0:2]))<<16 | uint32(buf[2]))
	} else {
		return 0
	}
}

// Marshal3 marshals AF as 3 bytes
func (af AF) Marshal3(dst []byte) []byte {
	dst = msb.AppendUint16(dst, uint16(af.Afi()))
	return append(dst, byte(af.Safi()))
}

func (af AF) Afi() AFI {
	return AFI(af >> 16)
}

func (af AF) IsAfi(afi AFI) bool {
	return af.Afi() == afi
}

func (af AF) Safi() SAFI {
	return SAFI(af)
}

func (af AF) IsSafi(safi SAFI) bool {
	return af.Safi() == safi
}

func (af AF) AddVal(val uint32) AFV {
	return NewAFV(af.Afi(), af.Safi(), val)
}

func (af AF) ToJSON(dst []byte) []byte {
	dst = append(dst, '"')
	dst = append(dst, af.Afi().String()...)
	dst = append(dst, '/')
	dst = append(dst, af.Safi().String()...)
	dst = append(dst, '"')
	return dst
}

func (af AF) ToJSONKey(dst []byte, key string) []byte {
	dst = append(dst, '"')
	dst = append(dst, key...)
	dst = append(dst, `":`...)
	return af.ToJSON(dst)
}

func (af *AF) FromJSON(src []byte) error {
	s1, s2, ok := strings.Cut(json.SQ(src), "/")
	if !ok {
		return json.ErrValue
	}

	afi, err := AFIString(s1)
	if err != nil {
		return err
	}

	safi, err := SAFIString(s2)
	if err != nil {
		return err
	}

	*af = NewAF(afi, safi)
	return nil
}
