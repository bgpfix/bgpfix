package msg

import (
	"sort"
)

// CAP_EXTENDED_NEXTHOP rfc8950
type CapExtNH struct {
	Proto map[AsafiVal]bool
}

func NewCapExtNH(cc CapCode) Cap {
	return &CapExtNH{make(map[AsafiVal]bool)}
}

func (c *CapExtNH) Unmarshal(buf []byte, caps Caps) error {
	for len(buf) > 0 {
		if len(buf) < 6 {
			return ErrLength
		}

		af := AfiSafiFrom(buf[0:4])
		nhf := Afi(msb.Uint16(buf[4:6]))
		buf = buf[6:]

		c.Add(af.Afi(), af.Safi(), nhf)
	}

	return nil
}

func (c *CapExtNH) Add(afi Afi, safi Safi, nhf Afi) {
	c.Proto[AfiSafiVal(afi, safi, uint32(nhf))] = true
}

func (c *CapExtNH) Has(afi Afi, safi Safi, nhf Afi) bool {
	return c.Proto[AfiSafiVal(afi, safi, uint32(nhf))]
}

func (c *CapExtNH) Drop(afi Afi, safi Safi, nhf Afi) {
	delete(c.Proto, AfiSafiVal(afi, safi, uint32(nhf)))
}

func (c *CapExtNH) Sorted() (dst []AsafiVal) {
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

func (c *CapExtNH) Common(cap2 Cap) Cap {
	c2, ok := cap2.(*CapExtNH)
	if !ok {
		return nil
	}

	dst := &CapExtNH{make(map[AsafiVal]bool)}
	for asv, val := range c.Proto {
		if val && c2.Proto[asv] {
			dst.Proto[asv] = true
		}
	}
	return dst
}

func (c *CapExtNH) Marshal(dst []byte) []byte {
	todo := c.Sorted()

	var step []AsafiVal
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

func (c *CapExtNH) ToJSON(dst []byte) []byte {
	dst = append(dst, '[')
	for i, as := range c.Sorted() {
		if i > 0 {
			dst = append(dst, `,`...)
		}
		dst = as.ToJSONAfi(dst)
	}
	return append(dst, ']')
}
