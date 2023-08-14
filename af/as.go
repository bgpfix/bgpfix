package af

import (
	"strings"
)

// AS represents AFI+SAFI as afi(16) + 0(8) + safi(8)
type AS uint32

// AfiSafi returns AS for given Afi and Safi
func AfiSafi(afi AFI, safi SAFI) AS {
	return AS(uint32(afi)<<16 | uint32(safi))
}

// AfiSafiFrom reads AS from wire representation in buf
func AfiSafiFrom(buf []byte) AS {
	if len(buf) == 4 {
		return AS(uint32(msb.Uint16(buf[0:2]))<<16 | uint32(buf[3]))
	} else if len(buf) == 3 {
		return AS(uint32(msb.Uint16(buf[0:2]))<<16 | uint32(buf[2]))
	} else {
		return 0
	}
}

// Marshal3 marshals AS as 3 bytes
func (as AS) Marshal3(dst []byte) []byte {
	dst = msb.AppendUint16(dst, uint16(as.Afi()))
	return append(dst, byte(as.Safi()))
}

func (as AS) Afi() AFI {
	return AFI(as >> 16)
}

func (as AS) Safi() SAFI {
	return SAFI(as)
}

func (as AS) ToJSON(dst []byte) []byte {
	dst = append(dst, '"')
	dst = append(dst, as.Afi().String()...)
	dst = append(dst, '/')
	dst = append(dst, as.Safi().String()...)
	dst = append(dst, '"')
	return dst
}

func (as AS) ToJSONKey(dst []byte, key string) []byte {
	dst = append(dst, '"')
	dst = append(dst, key...)
	dst = append(dst, `":`...)
	return as.ToJSON(dst)
}

func (as *AS) FromJSON(src []byte) error {
	s1, s2, ok := strings.Cut(bsu(src), "/")
	if !ok {
		return ErrValue
	}

	afi, err := AFIString(s1)
	if err != nil {
		return err
	}

	safi, err := SAFIString(s2)
	if err != nil {
		return err
	}

	*as = AfiSafi(afi, safi)
	return nil
}
