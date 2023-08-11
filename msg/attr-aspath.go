package msg

import (
	"fmt"
	"strconv"

	jsp "github.com/buger/jsonparser"
)

// ATTR_ASPATH or ATTR_AS4PATH
type AttrAspath struct {
	AttrType
	Segments []AspathSegment
}

// AspathSegment represents an AS_PATH segment
type AspathSegment struct {
	IsSet bool     // true iff segment is an AS_SET
	List  []uint32 // list of AS numbers
}

func NewAttrAspath(at AttrType) Attr {
	return &AttrAspath{AttrType: at}
}

func (a *AttrAspath) Unmarshal(buf []byte, caps Caps) error {
	// support an actually common case: empty AS_PATH
	if len(buf) == 0 {
		return nil
	}

	// asn length
	asnlen := 2
	if a.Code() == ATTR_AS4PATH || caps.Has(CAP_AS4) {
		asnlen = 4
	}

	for len(buf) >= 2 {
		var seg AspathSegment

		// is AS_SET?
		switch buf[0] {
		case 1:
			seg.IsSet = true // is AS_SET
		case 2:
			// is AS_SEQUENCE
		default:
			return fmt.Errorf("%w: %d", ErrSegType, buf[0])
		}

		// total length?
		tl := 2 + asnlen*int(buf[1])
		if len(buf) < tl {
			return ErrSegLen
		}

		// read ASNs
		todo := buf[2:]
		for len(todo) >= asnlen {
			if asnlen == 4 {
				seg.List = append(seg.List, msb.Uint32(todo))
			} else {
				seg.List = append(seg.List, uint32(msb.Uint16(todo)))
			}
			todo = todo[asnlen:]
		}

		// store segment, go to next
		a.Segments = append(a.Segments, seg)
		buf = buf[tl:]
	}

	if len(buf) == 0 {
		return nil
	} else {
		return ErrLength
	}
}

func (a *AttrAspath) Marshal(dst []byte, caps Caps) []byte {
	// asn length
	asnlen := 2
	if a.Code() == ATTR_AS4PATH || caps.Has(CAP_AS4) {
		asnlen = 4
	}

	// total length
	l := 0
	for _, seg := range a.Segments {
		l += 1 + 1 + asnlen*len(seg.List)
	}

	// attr flags, code, length
	dst = a.AttrType.MarshalLen(dst, l)

	// attr value
	for _, seg := range a.Segments {
		if seg.IsSet {
			dst = append(dst, 1)
		} else {
			dst = append(dst, 2)
		}
		dst = append(dst, byte(len(seg.List)))
		for _, hop := range seg.List {
			if asnlen == 4 {
				dst = msb.AppendUint32(dst, hop)
			} else {
				dst = msb.AppendUint16(dst, uint16(hop))
			}
		}
	}

	return dst
}

func (a *AttrAspath) ToJSON(dst []byte) []byte {
	dst = append(dst, '[')
	for i := range a.Segments {
		seg := &a.Segments[i]
		if i > 0 {
			dst = append(dst, ',')
		}

		if seg.IsSet {
			dst = append(dst, '[')
		}

		for j, asn := range seg.List {
			if j > 0 {
				dst = append(dst, ',')
			}
			dst = strconv.AppendUint(dst, uint64(asn), 10)
		}

		if seg.IsSet {
			dst = append(dst, ']')
		}
	}
	dst = append(dst, ']')
	return dst
}

func (a *AttrAspath) FromJSON(src []byte) (reterr error) {
	defer func() {
		if r, ok := recover().(string); ok {
			reterr = fmt.Errorf("%w: %s", ErrValue, r)
		}
	}()

	parse_set := func(src []byte) {
		seg := AspathSegment{IsSet: true}
		jsp.ArrayEach(src, func(value []byte, dataType jsp.ValueType, _ int, _ error) {
			if dataType != jsp.Number {
				panic("AS_SET not number")
			}

			v, err := strconv.ParseUint(bs(value), 0, 32)
			if err != nil {
				panic("AS_SET invalid value")
			}

			seg.List = append(seg.List, uint32(v))
		})
		if len(seg.List) > 0 {
			a.Segments = append(a.Segments, seg)
		}
	}

	var seg AspathSegment
	jsp.ArrayEach(src, func(value []byte, dataType jsp.ValueType, _ int, _ error) {
		// is an AS_SET?
		if dataType == jsp.Array {
			if len(seg.List) > 0 {
				a.Segments = append(a.Segments, seg)
				seg = AspathSegment{} // clear
			}
			parse_set(value)
			return
		}

		if dataType != jsp.Number {
			panic("AS_PATH not number")
		}

		v, err := strconv.ParseUint(bs(value), 0, 32)
		if err != nil {
			panic("AS_PATH invalid value")
		}

		seg.List = append(seg.List, uint32(v))
	})
	if len(seg.List) > 0 {
		a.Segments = append(a.Segments, seg)
	}
	return
}
