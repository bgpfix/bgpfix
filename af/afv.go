package af

import (
	"strconv"
	"strings"

	"github.com/bgpfix/bgpfix/json"
)

// AFV represents AFI+SAFI+VAL as afi(16) + 0(8) + safi(8) + val(32)
type AFV uint64

func NewAFV(afi AFI, safi SAFI, val uint32) AFV {
	return AFV(uint64(afi)<<48 | uint64(safi)<<32 | uint64(val))
}

func (afv AFV) Afi() AFI {
	return AFI(afv >> 48)
}

func (afv AFV) Safi() SAFI {
	return SAFI(afv >> 32)
}

func (afv AFV) Val() uint32 {
	return uint32(afv)
}

func (afv AFV) DropVal() AF {
	return NewAF(afv.Afi(), afv.Safi())
}

// Marshal4 marshals AFV as 4 bytes: afi(16) + safi(8) + val(8)
func (afv AFV) Marshal4(dst []byte) []byte {
	dst = msb.AppendUint16(dst, uint16(afv.Afi()))
	dst = append(dst, byte(afv.Safi()))
	return append(dst, byte(afv.Val()))
}

// ToJSON marshals afv to JSON, optionally using vs for VAL if non-empty.
func (afv AFV) ToJSON(dst []byte, vs string) []byte {
	dst = append(dst, '"')
	dst = append(dst, afv.Afi().String()...)
	dst = append(dst, '/')
	dst = append(dst, afv.Safi().String()...)
	dst = append(dst, '/')
	if vs == "" {
		dst = strconv.AppendUint(dst, uint64(afv.Val()), 10)
	} else {
		dst = append(dst, vs...)
	}
	dst = append(dst, '"')
	return dst
}

// FromJSON unmarshals afv from JSON, optionally using vs for parsing VAL if non-nil.
func (afv *AFV) FromJSON(src []byte, vs func(string) (uint32, error)) error {
	d := strings.Split(json.SQ(src), "/")
	if len(d) != 3 {
		return json.ErrValue
	}

	afi, err := AFIString(d[0])
	if err != nil {
		return err
	}

	safi, err := SAFIString(d[1])
	if err != nil {
		return err
	}

	if vs == nil {
		val, err := strconv.ParseUint(d[2], 10, 32)
		if err != nil {
			return err
		}
		*afv = NewAFV(afi, safi, uint32(val))
	} else {
		val, err := vs(d[2])
		if err != nil {
			return err
		}
		*afv = NewAFV(afi, safi, val)
	}

	return nil
}
