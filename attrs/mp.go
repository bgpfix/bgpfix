package attrs

import (
	"github.com/bgpfix/bgpfix/af"
	"github.com/bgpfix/bgpfix/caps"
	jsp "github.com/buger/jsonparser"
)

// MP represents ATTR_MP_REACH and ATTR_MP_UNREACH attributes
type MP struct {
	CodeFlags
	af.AS

	NH    []byte  // only for ATTR_MP_REACH
	Data  []byte  // NLRI or unreachable
	Value MPValue // interpreted NH / Data (may be nil)
}

// MP attribute Value
type MPValue interface {
	// Afi returns the AFI of the parent
	Afi() af.AFI

	// Safi returns the SAFI of the parent
	Safi() af.SAFI

	// Unmarshal parses wire representation from the parent
	Unmarshal(cps caps.Caps) error

	// Marshal writes wire representation to the parent
	Marshal(cps caps.Caps)

	// ToJSON appends *JSON keys* to dst (will be embedded in the parent object)
	ToJSON(dst []byte) []byte

	// FromJSON reads from JSON object in src (full parent object)
	FromJSON(src []byte) error
}

// MPNewFunc returns new ATTR_MP_* value for afi/safi in mp
type MPNewFunc func(mp *MP) MPValue

// MPNewFuncs maps ATTR_MP_* afi/safi pairs to their NewFunc
var MPNewFuncs = map[af.AS]MPNewFunc{
	af.AfiSafi(af.AFI_IPV4, af.SAFI_UNICAST):  NewMPPrefixes,
	af.AfiSafi(af.AFI_IPV4, af.SAFI_FLOWSPEC): NewMPFlowspec,

	af.AfiSafi(af.AFI_IPV6, af.SAFI_UNICAST):  NewMPPrefixes,
	af.AfiSafi(af.AFI_IPV6, af.SAFI_FLOWSPEC): NewMPFlowspec,
}

func NewMP(at CodeFlags) Attr {
	return &MP{CodeFlags: at}
}

func (mp *MP) Unmarshal(buf []byte, cps caps.Caps) error {
	// afi + safi
	if len(buf) < 3 {
		return ErrLength
	}
	mp.AS = af.AfiSafiFrom(buf[0:3])
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
	if newfunc, ok := MPNewFuncs[mp.AS]; ok {
		mp.Value = newfunc(mp)
		return mp.Value.Unmarshal(cps)
	}

	return nil
}

func (mp *MP) Marshal(dst []byte, cps caps.Caps) []byte {
	if mp.Value != nil {
		mp.Value.Marshal(cps)
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
			dst = jsonHex(dst, mp.NH)
			dst = append(dst, ',')
		}
		dst = append(dst, `"data":`...)
		dst = jsonHex(dst, mp.Data)
	}
	return append(dst, '}')
}

func (mp *MP) FromJSON(src []byte) error {
	// has "af"?
	afsrc, _, _, err := jsp.Get(src, "af")
	if err != nil {
		return ErrValue
	}

	// decode afi/safi
	err = mp.AS.FromJSON(afsrc)
	if err != nil {
		return err
	}

	// do we have a parser for it?
	if newfunc, ok := MPNewFuncs[mp.AS]; ok {
		mp.Value = newfunc(mp)
		return mp.Value.FromJSON(src)
	} // else nope, parse "nh"

	// has "nh"?
	if v, _, _, err := jsp.Get(src, "nh"); err == nil {
		mp.NH, err = unjsonHex(mp.NH[:0], v)
		if err != nil {
			return err
		}
	}

	// has "data"?
	if v, _, _, err := jsp.Get(src, "data"); err == nil {
		mp.Data, err = unjsonHex(mp.Data[:0], v)
		if err != nil {
			return err
		}
	}

	return nil // success
}
