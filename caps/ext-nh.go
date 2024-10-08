package caps

import (
	"slices"

	"github.com/bgpfix/bgpfix/afi"
	"github.com/bgpfix/bgpfix/json"
)

// ExtNH implements CAP_EXTENDED_NEXTHOP rfc8950
type ExtNH struct {
	Proto map[afi.ASV]bool
}

func NewExtNH(cc Code) Cap {
	return &ExtNH{make(map[afi.ASV]bool)}
}

func (c *ExtNH) Unmarshal(buf []byte, caps Caps) error {
	for len(buf) > 0 {
		if len(buf) < 6 {
			return ErrLength
		}

		asf := afi.NewASBytes(buf[0:4])
		nhf := afi.NewAFIBytes(buf[4:6])
		buf = buf[6:]

		c.Add(asf, nhf)
	}

	return nil
}

func (c *ExtNH) Add(as afi.AS, nhf afi.AFI) {
	c.Proto[as.AddVal(uint32(nhf))] = true
}

func (c *ExtNH) Has(as afi.AS, nhf afi.AFI) bool {
	return c.Proto[as.AddVal(uint32(nhf))]
}

func (c *ExtNH) Drop(as afi.AS, nhf afi.AFI) {
	delete(c.Proto, as.AddVal(uint32(nhf)))
}

func (c *ExtNH) Sorted() (dst []afi.ASV) {
	for asv, val := range c.Proto {
		if val {
			dst = append(dst, asv)
		}
	}
	slices.Sort(dst)
	return
}

func (c *ExtNH) Intersect(cap2 Cap) Cap {
	c2, ok := cap2.(*ExtNH)
	if !ok {
		return nil
	}

	dst := &ExtNH{make(map[afi.ASV]bool)}
	for asv, val := range c.Proto {
		if val && c2.Proto[asv] {
			dst.Proto[asv] = true
		}
	}
	return dst
}

func (c *ExtNH) Marshal(dst []byte) []byte {
	todo := c.Sorted()

	var step []afi.ASV
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
	for i, afv := range c.Sorted() {
		if i > 0 {
			dst = append(dst, `,`...)
		}
		afi2 := afi.AFI(afv.Val())
		dst = afv.ToJSON(dst, afi2.String())
	}
	return append(dst, ']')
}

func (c *ExtNH) FromJSON(src []byte) (err error) {
	return json.ArrayEach(src, func(key int, val []byte, typ json.Type) error {
		var asv afi.ASV
		err := asv.FromJSON(val, func(s string) (uint32, error) {
			afi2, err := afi.AFIString(s)
			return uint32(afi2), err
		})
		if err != nil {
			return err
		}
		c.Proto[asv] = true
		return nil
	})
}
