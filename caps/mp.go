package caps

import (
	"sort"

	"github.com/bgpfix/bgpfix/af"
	"github.com/bgpfix/bgpfix/json"
)

// MP implements CAP_MP rfc4760
type MP struct {
	Proto map[af.AF]bool
}

func NewMP(cc Code) Cap {
	return &MP{make(map[af.AF]bool)}
}

func (c *MP) Unmarshal(buf []byte, caps Caps) error {
	if len(buf) != 4 {
		return ErrLength
	}

	// ignore buf[2]
	af := af.NewASBytes(buf[:4])
	c.Add(af.Afi(), af.Safi())
	return nil
}

func (c *MP) Add(afi af.AFI, safi af.SAFI) {
	c.Proto[af.New(afi, safi)] = true
}

func (c *MP) Has(afi af.AFI, safi af.SAFI) bool {
	return c.Proto[af.New(afi, safi)]
}

func (c *MP) Drop(afi af.AFI, safi af.SAFI) {
	delete(c.Proto, af.New(afi, safi))
}

func (c *MP) Sorted() (dst []af.AF) {
	for as, val := range c.Proto {
		if val {
			dst = append(dst, as)
		}
	}
	sort.Slice(dst, func(i, j int) bool {
		return dst[i] < dst[j]
	})
	return
}

func (c *MP) Intersect(cap2 Cap) Cap {
	c2, ok := cap2.(*MP)
	if !ok {
		return nil
	}

	dst := &MP{
		Proto: make(map[af.AF]bool),
	}
	for as, val := range c.Proto {
		if val && c2.Proto[as] {
			dst.Proto[as] = true
		}
	}
	return dst
}

func (c *MP) Marshal(dst []byte) []byte {
	for _, as := range c.Sorted() {
		dst = append(dst, byte(CAP_MP), 4)
		dst = msb.AppendUint32(dst, uint32(as))
	}
	return dst
}

func (c *MP) ToJSON(dst []byte) []byte {
	dst = append(dst, '[')
	for i, as := range c.Sorted() {
		if i > 0 {
			dst = append(dst, `,`...)
		}
		dst = as.ToJSON(dst)
	}
	return append(dst, ']')
}

func (c *MP) FromJSON(src []byte) (err error) {
	var as af.AF
	return json.ArrayEach(src, func(key int, val []byte, typ json.Type) error {
		if err := as.FromJSON(val); err != nil {
			return err
		}
		c.Proto[as] = true
		return nil
	})
}
