package attrs

import (
	"bytes"
	"errors"
	"strconv"

	"github.com/bgpfix/bgpfix/caps"
	jsp "github.com/buger/jsonparser"
)

// Community represents ATTR_COMMUNITY
type Community struct {
	CodeFlags
	ASN   []uint16
	Value []uint16
}

func NewCommunity(at CodeFlags) Attr {
	return &Community{CodeFlags: at}
}

func (a *Community) Unmarshal(buf []byte, cps caps.Caps) error {
	for len(buf) > 0 {
		if len(buf) < 4 {
			return ErrLength
		}
		raw := msb.Uint32(buf)
		buf = buf[4:]
		a.Add(uint16(raw>>16), uint16(raw))
	}
	return nil
}

func (a *Community) Add(asn uint16, value uint16) {
	a.ASN = append(a.ASN, asn)
	a.Value = append(a.Value, value)
}

func (a *Community) Marshal(dst []byte, cps caps.Caps) []byte {
	tl := 4 * len(a.ASN)
	dst = a.CodeFlags.MarshalLen(dst, tl)
	for i := range a.ASN {
		dst = msb.AppendUint16(dst, a.ASN[i])
		dst = msb.AppendUint16(dst, a.Value[i])
	}
	return dst
}

func (a *Community) ToJSON(dst []byte) []byte {
	dst = append(dst, '[')
	for i := range a.ASN {
		if i > 0 {
			dst = append(dst, `,"`...)
		} else {
			dst = append(dst, `"`...)
		}
		dst = strconv.AppendUint(dst, uint64(a.ASN[i]), 10)
		dst = append(dst, ':')
		dst = strconv.AppendUint(dst, uint64(a.Value[i]), 10)
		dst = append(dst, '"')
	}
	return append(dst, ']')
}

func (a *Community) FromJSON(src []byte) error {
	sep := []byte(":")
	var errs []error
	jsp.ArrayEach(src, func(value []byte, dataType jsp.ValueType, _ int, _ error) {
		if dataType != jsp.String {
			return
		}

		d := bytes.Split(value, sep)
		if len(d) != 2 {
			errs = append(errs, ErrValue)
			return
		}

		asn, err := strconv.ParseUint(bs(d[0]), 0, 16)
		if err != nil {
			errs = append(errs, err)
			return
		}

		val, err := strconv.ParseUint(bs(d[1]), 0, 16)
		if err != nil {
			errs = append(errs, err)
			return
		}

		a.Add(uint16(asn), uint16(val))
	})
	return errors.Join(errs...)
}
