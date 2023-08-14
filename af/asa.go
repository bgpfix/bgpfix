package af

// ASVal represents AFI+SAFI+VAL as afi(16) + 0(8) + safi(8) + val(32)
type ASVal uint64

func AfiSafiVal(afi AFI, safi SAFI, val uint32) ASVal {
	return ASVal(uint64(afi)<<48 | uint64(safi)<<32 | uint64(val))
}

func (asv ASVal) Afi() AFI {
	return AFI(asv >> 48)
}

func (asv ASVal) Safi() SAFI {
	return SAFI(asv >> 32)
}

func (asv ASVal) Val() uint32 {
	return uint32(asv)
}

// ToJSONAfi interprets Val as an AFI
func (asv ASVal) ToJSONAfi(dst []byte) []byte {
	dst = append(dst, '"')
	dst = append(dst, asv.Afi().String()...)
	dst = append(dst, '/')
	dst = append(dst, asv.Safi().String()...)
	dst = append(dst, '/')
	afi := AFI(asv.Val())
	dst = append(dst, afi.String()...)
	dst = append(dst, '"')
	return dst
}
