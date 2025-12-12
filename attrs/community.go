package attrs

import (
	"bytes"
	"strconv"

	"github.com/bgpfix/bgpfix/caps"
	"github.com/bgpfix/bgpfix/dir"
	"github.com/bgpfix/bgpfix/json"
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

func (a *Community) Reset() {
	a.ASN = a.ASN[:0]
	a.Value = a.Value[:0]
}

func (a *Community) Len() int {
	if a != nil {
		return len(a.ASN)
	} else {
		return 0
	}
}

func (a *Community) Unmarshal(buf []byte, cps caps.Caps, dir dir.Dir) error {
	exp := len(buf) / 4
	if len(a.ASN) == 0 && cap(a.ASN) < exp {
		a.ASN = make([]uint16, 0, exp)
		a.Value = make([]uint16, 0, exp)
	}
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

func (a *Community) Marshal(dst []byte, cps caps.Caps, dir dir.Dir) []byte {
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
	return json.ArrayEach(src, func(key int, val []byte, typ json.Type) error {
		d := bytes.Split(val, sep)
		if len(d) != 2 {
			return ErrValue
		}

		asn, err := strconv.ParseUint(json.S(d[0]), 0, 16)
		if err != nil {
			return err
		}

		cval, err := strconv.ParseUint(json.S(d[1]), 0, 16)
		if err != nil {
			return err
		}

		a.Add(uint16(asn), uint16(cval))
		return nil
	})
}
