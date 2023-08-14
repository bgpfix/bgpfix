package attrs

import (
	"bytes"
	"errors"
	"strconv"

	"github.com/bgpfix/bgpfix/caps"
	jsp "github.com/buger/jsonparser"
)

// LargeCom represents ATTR_LARGE_COMMUNITY
type LargeCom struct {
	CodeFlags

	ASN    []uint32 // Global Administrator
	Value1 []uint32 // Local Data Part 1
	Value2 []uint32 // Local Data Part 2
}

func NewLargeCom(at CodeFlags) Attr {
	return &LargeCom{CodeFlags: at}
}

func (a *LargeCom) Unmarshal(buf []byte, cps caps.Caps) error {
	for len(buf) > 0 {
		if len(buf) < 12 {
			return ErrLength
		}
		a.Add(
			msb.Uint32(buf[0:4]),
			msb.Uint32(buf[4:8]),
			msb.Uint32(buf[8:12]))
		buf = buf[12:]
	}

	return nil
}

func (a *LargeCom) Add(asn, value1, value2 uint32) {
	a.ASN = append(a.ASN, asn)
	a.Value1 = append(a.Value1, value1)
	a.Value2 = append(a.Value2, value2)
}

func (a *LargeCom) Marshal(dst []byte, cps caps.Caps) []byte {
	tl := 12 * len(a.ASN)
	dst = a.CodeFlags.MarshalLen(dst, tl)
	for i := range a.ASN {
		dst = msb.AppendUint32(dst, a.ASN[i])
		dst = msb.AppendUint32(dst, a.Value1[i])
		dst = msb.AppendUint32(dst, a.Value2[i])
	}
	return dst
}

func (a *LargeCom) ToJSON(dst []byte) []byte {
	dst = append(dst, '[')
	for i := range a.ASN {
		if i > 0 {
			dst = append(dst, `,"`...)
		} else {
			dst = append(dst, `"`...)
		}
		dst = strconv.AppendUint(dst, uint64(a.ASN[i]), 10)
		dst = append(dst, ':')
		dst = strconv.AppendUint(dst, uint64(a.Value1[i]), 10)
		dst = append(dst, ':')
		dst = strconv.AppendUint(dst, uint64(a.Value2[i]), 10)
		dst = append(dst, '"')
	}
	return append(dst, ']')
}

func (a *LargeCom) FromJSON(src []byte) error {
	sep := []byte(":")
	var errs []error
	jsp.ArrayEach(src, func(value []byte, dataType jsp.ValueType, _ int, _ error) {
		if dataType != jsp.String {
			return
		}

		d := bytes.Split(value, sep)
		if len(d) != 3 {
			errs = append(errs, ErrValue)
			return
		}

		asn, err := strconv.ParseUint(bs(d[0]), 0, 32)
		if err != nil {
			errs = append(errs, err)
			return
		}

		val1, err := strconv.ParseUint(bs(d[1]), 0, 32)
		if err != nil {
			errs = append(errs, err)
			return
		}

		val2, err := strconv.ParseUint(bs(d[2]), 0, 32)
		if err != nil {
			errs = append(errs, err)
			return
		}

		a.Add(uint32(asn), uint32(val1), uint32(val2))
	})
	return errors.Join(errs...)
}
