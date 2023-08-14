package caps

import (
	"sort"

	"github.com/bgpfix/bgpfix/af"
)

// ExtNH implements CAP_EXTENDED_NEXTHOP rfc8950
type ExtNH struct {
	Proto map[af.ASVal]bool
}

func NewExtNH(cc Code) Cap {
	return &ExtNH{make(map[af.ASVal]bool)}
}

func (c *ExtNH) Unmarshal(buf []byte, caps Caps) error {
	for len(buf) > 0 {
		if len(buf) < 6 {
			return ErrLength
		}

		asf := af.AfiSafiFrom(buf[0:4])
		nhf := af.AFI(msb.Uint16(buf[4:6]))
		buf = buf[6:]

		c.Add(asf.Afi(), asf.Safi(), nhf)
	}

	return nil
}

func (c *ExtNH) Add(afi af.AFI, safi af.SAFI, nhf af.AFI) {
	c.Proto[af.AfiSafiVal(afi, safi, uint32(nhf))] = true
}

func (c *ExtNH) Has(afi af.AFI, safi af.SAFI, nhf af.AFI) bool {
	return c.Proto[af.AfiSafiVal(afi, safi, uint32(nhf))]
}

func (c *ExtNH) Drop(afi af.AFI, safi af.SAFI, nhf af.AFI) {
	delete(c.Proto, af.AfiSafiVal(afi, safi, uint32(nhf)))
}

func (c *ExtNH) Sorted() (dst []af.ASVal) {
	for asv, val := range c.Proto {
		if val {
			dst = append(dst, asv)
		}
	}
	sort.Slice(dst, func(i, j int) bool {
		return dst[i] < dst[j]
	})
	return
}

func (c *ExtNH) Common(cap2 Cap) Cap {
	c2, ok := cap2.(*ExtNH)
	if !ok {
		return nil
	}

	dst := &ExtNH{make(map[af.ASVal]bool)}
	for asv, val := range c.Proto {
		if val && c2.Proto[asv] {
			dst.Proto[asv] = true
		}
	}
	return dst
}

func (c *ExtNH) Marshal(dst []byte) []byte {
	todo := c.Sorted()

	var step []af.ASVal
	for len(todo) > 0 {
		if len(todo) > 42 {
			dst = append(dst, byte(CAP_EXTENDED_NEXTHOP), 6*42)
			step = todo[:43] // the first 42 elements
			todo = todo[43:]
		} else {
			dst = append(dst, byte(CAP_EXTENDED_NEXTHOP), byte(6*len(todo)))
			step = todo // all
			todo = nil  // last iteration
		}

		for _, asv := range step {
			dst = msb.AppendUint16(dst, uint16(asv.Afi()))
			dst = msb.AppendUint16(dst, uint16(asv.Safi()))
			dst = msb.AppendUint16(dst, uint16(asv.Val()))
		}
	}

	return dst
}

func (c *ExtNH) ToJSON(dst []byte) []byte {
	dst = append(dst, '[')
	for i, as := range c.Sorted() {
		if i > 0 {
			dst = append(dst, `,`...)
		}
		dst = as.ToJSONAfi(dst)
	}
	return append(dst, ']')
}
