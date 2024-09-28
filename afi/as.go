// Package af implements AFI, SAFI, and combinations
package afi

import (
	"strings"

	"github.com/bgpfix/bgpfix/binary"
	"github.com/bgpfix/bgpfix/json"
)

var msb = binary.Msb

// AS represents AFI+SAFI as afi(16) + 0(8) + safi(8)
type AS uint32

// common AFI + SAFI combinations
var (
	AS_INVALID = NewAS(AFI_INVALID, SAFI_INVALID)

	AS_IPV4_UNICAST   = NewAS(AFI_IPV4, SAFI_UNICAST)
	AS_IPV4_MULTICAST = NewAS(AFI_IPV4, SAFI_MULTICAST)
	AS_IPV4_FLOWSPEC  = NewAS(AFI_IPV4, SAFI_FLOWSPEC)

	AS_IPV6_UNICAST   = NewAS(AFI_IPV6, SAFI_UNICAST)
	AS_IPV6_MULTICAST = NewAS(AFI_IPV6, SAFI_MULTICAST)
	AS_IPV6_FLOWSPEC  = NewAS(AFI_IPV6, SAFI_FLOWSPEC)
)

// NewAS returns AS for given Afi and Safi
func NewAS(afi AFI, safi SAFI) AS {
	return AS(uint32(afi)<<16 | uint32(safi))
}

// NewASBytes reads AS from wire representation in buf
func NewASBytes(buf []byte) AS {
	if len(buf) == 4 {
		return AS(uint32(msb.Uint16(buf[0:2]))<<16 | uint32(buf[3]))
	} else if len(buf) == 3 {
		return AS(uint32(msb.Uint16(buf[0:2]))<<16 | uint32(buf[2]))
	} else {
		return 0
	}
}

// Marshal3 marshals AS as 3 bytes
func (af AS) Marshal3(dst []byte) []byte {
	dst = msb.AppendUint16(dst, uint16(af.Afi()))
	return append(dst, byte(af.Safi()))
}

func (af AS) Afi() AFI {
	return AFI(af >> 16)
}

func (af AS) IsIPv4() bool {
	return af.Afi() == AFI_IPV4
}

func (af AS) IsIPv6() bool {
	return af.Afi() == AFI_IPV6
}

func (af AS) Safi() SAFI {
	return SAFI(af)
}

func (af AS) AddVal(val uint32) ASV {
	return NewASV(af.Afi(), af.Safi(), val)
}

func (af AS) ToJSON(dst []byte) []byte {
	dst = append(dst, '"')
	dst = append(dst, af.Afi().String()...)
	dst = append(dst, '/')
	dst = append(dst, af.Safi().String()...)
	dst = append(dst, '"')
	return dst
}

func (af AS) ToJSONKey(dst []byte, key string) []byte {
	dst = append(dst, '"')
	dst = append(dst, key...)
	dst = append(dst, `":`...)
	return af.ToJSON(dst)
}

func (af *AS) FromJSON(src []byte) error {
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

	*af = NewAS(afi, safi)
	return nil
}
