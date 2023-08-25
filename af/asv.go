package af

import (
	"strings"

	"github.com/bgpfix/bgpfix/json"
)

// ASV represents AFI+SAFI+VAL as afi(16) + 0(8) + safi(8) + val(32)
type ASV uint64

func AfiSafiVal(afi AFI, safi SAFI, val uint32) ASV {
	return ASV(uint64(afi)<<48 | uint64(safi)<<32 | uint64(val))
}

func (asv ASV) Afi() AFI {
	return AFI(asv >> 48)
}

func (asv ASV) Safi() SAFI {
	return SAFI(asv >> 32)
}

func (asv ASV) Val() uint32 {
	return uint32(asv)
}

// ToJSONAfi interprets Val as an AFI
func (asv ASV) ToJSONAfi(dst []byte) []byte {
	dst = append(dst, '"')
	dst = append(dst, asv.Afi().String()...)
	dst = append(dst, '/')
	dst = append(dst, asv.Safi().String()...)
	dst = append(dst, '/')
	afi2 := AFI(asv.Val())
	dst = append(dst, afi2.String()...)
	dst = append(dst, '"')
	return dst
}

// FromJSONAfi interprets Val as an AFI
func (asv *ASV) FromJSONAfi(src []byte) error {
	d := strings.Split(json.SQ(src), "/")
	if len(d) != 3 {
		return ErrValue
	}

	afi, err := AFIString(d[0])
	if err != nil {
		return err
	}

	safi, err := SAFIString(d[1])
	if err != nil {
		return err
	}

	afi2, err := AFIString(d[2])
	if err != nil {
		return err
	}

	*asv = AfiSafiVal(afi, safi, uint32(afi2))
	return nil
}
