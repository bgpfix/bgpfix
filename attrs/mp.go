package attrs

import (
	"github.com/bgpfix/bgpfix/afi"
	"github.com/bgpfix/bgpfix/caps"
	"github.com/bgpfix/bgpfix/dir"
	"github.com/bgpfix/bgpfix/json"
)

// MP represents ATTR_MP_REACH and ATTR_MP_UNREACH attributes
type MP struct {
	CodeFlags
	afi.AS

	NH    []byte  // only for ATTR_MP_REACH
	Data  []byte  // NLRI or unreachable
	Value MPValue // interpreted NH / Data (may be nil)
}

// MP attribute Value
type MPValue interface {
	// Afi returns the AFI of the parent
	Afi() afi.AFI

	// Safi returns the SAFI of the parent
	Safi() afi.SAFI

	// Unmarshal parses wire representation from the parent
	Unmarshal(cps caps.Caps, dir dir.Dir) error

	// Marshal writes wire representation to the parent
	Marshal(cps caps.Caps, dir dir.Dir)

	// ToJSON appends *JSON keys* to dst (will be embedded in the parent object)
	ToJSON(dst []byte) []byte

	// FromJSON reads from JSON object in src (full parent object)
	FromJSON(src []byte) error
}

// MPNewFunc returns new ATTR_MP_* value for afi/safi in mp
type MPNewFunc func(mp *MP) MPValue

// MPNewFuncs maps ATTR_MP_* afi/safi pairs to their NewFunc
var MPNewFuncs = map[afi.AS]MPNewFunc{
	afi.AS_IPV4_UNICAST:  NewMPPrefixes,
	afi.AS_IPV4_FLOWSPEC: NewMPFlowspec,
	afi.AS_IPV6_UNICAST:  NewMPPrefixes,
	afi.AS_IPV6_FLOWSPEC: NewMPFlowspec,
}

func NewMP(at CodeFlags) Attr {
	return &MP{CodeFlags: at}
}

// NewMPValue returns a new MPValue for parent mp,
// or nil if its AFI/SAFI pair is not supported.
func NewMPValue(mp *MP) MPValue {
	if newfunc, ok := MPNewFuncs[mp.AS]; ok {
		return newfunc(mp)
	} else {
		return nil
	}
}

func (mp *MP) Unmarshal(buf []byte, cps caps.Caps, dir dir.Dir) error {
	// afi + safi
	if len(buf) < 3 {
		return ErrLength
	}
	mp.AS = afi.NewASBytes(buf[0:3])
	buf = buf[3:]

	// nexthop?
	if mp.Code() == ATTR_MP_REACH {
		if len(buf) < 2 {
			return ErrLength
		}

		nhl := int(buf[0])
		buf = buf[1:]
		if len(buf) < nhl+1 {
			return ErrLength
		}
		mp.NH = buf[:nhl]

		buf = buf[nhl+1:] // skip the reserved byte
	}

	// nlri
	mp.Data = buf

	// parse the value?
	mp.Value = NewMPValue(mp)
	if mp.Value != nil {
		return mp.Value.Unmarshal(cps, dir)
	}

	return nil
}

func (mp *MP) Marshal(dst []byte, cps caps.Caps, dir dir.Dir) []byte {
	if mp.Value != nil {
		mp.Value.Marshal(cps, dir)
	}

	tl := 2 + 1 + len(mp.Data) // afi + safi + nlri
	if mp.Code() == ATTR_MP_REACH {
		tl += 1 + len(mp.NH) + 1 // next-hop len + data + reserved
	}
	dst = mp.CodeFlags.MarshalLen(dst, tl)

	dst = mp.AS.Marshal3(dst)
	if mp.Code() == ATTR_MP_REACH {
		dst = append(dst, byte(len(mp.NH)))
		dst = append(dst, mp.NH...)
		dst = append(dst, 0) // reserved byte
	}

	return append(dst, mp.Data...)
}

func (mp *MP) ToJSON(dst []byte) []byte {
	dst = append(dst, '{')
	dst = mp.AS.ToJSONKey(dst, "af")
	dst = append(dst, ',')

	if mp.Value != nil {
		dst = mp.Value.ToJSON(dst)
	} else {
		if mp.Code() == ATTR_MP_REACH && len(mp.NH) > 0 {
			dst = append(dst, `"nh":`...)
			dst = json.Hex(dst, mp.NH)
			dst = append(dst, ',')
		}
		dst = append(dst, `"data":`...)
		dst = json.Hex(dst, mp.Data)
	}
	return append(dst, '}')
}

func (mp *MP) FromJSON(src []byte) error {
	// parse generic attributes
	err := json.ObjectEach(src, func(key string, val []byte, typ json.Type) (err error) {
		switch key {
		case "af":
			err = mp.AS.FromJSON(val)
		case "nh":
			mp.NH, err = json.UnHex(val, mp.NH[:0])
		case "data":
			mp.Data, err = json.UnHex(val, mp.Data[:0])
		}
		return err
	})
	if err != nil {
		return err
	}

	// do we have a specific parser for it?
	mp.Value = NewMPValue(mp)
	if mp.Value != nil {
		return mp.Value.FromJSON(src)
	}
	return nil
}

// Prefixes returns mp.Value interpreted as MPPrefixes, or nil on error
func (mp *MP) Prefixes() *MPPrefixes {
	if mp == nil || mp.Value == nil {
		return nil
	}

	pfx, _ := mp.Value.(*MPPrefixes)
	return pfx
}
