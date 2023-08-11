package msg

import (
	"sort"
)

// CAP_MULTIPROTOCOL rfc4760
type CapMP struct {
	Proto map[Asafi]bool
}

func NewCapMP(cc CapCode) Cap {
	return &CapMP{
		Proto: make(map[Asafi]bool),
	}
}

func (c *CapMP) Unmarshal(buf []byte, caps Caps) error {
	if len(buf) != 4 {
		return ErrLength
	}

	// ignore buf[2]
	af := AfiSafiFrom(buf[:4])
	c.Add(af.Afi(), af.Safi())
	return nil
}

func (c *CapMP) Add(afi Afi, safi Safi) {
	c.Proto[AfiSafi(afi, safi)] = true
}

func (c *CapMP) Has(afi Afi, safi Safi) bool {
	return c.Proto[AfiSafi(afi, safi)]
}

func (c *CapMP) Drop(afi Afi, safi Safi) {
	delete(c.Proto, AfiSafi(afi, safi))
}

func (c *CapMP) Sorted() (dst []Asafi) {
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

func (c *CapMP) Common(cap2 Cap) Cap {
	c2, ok := cap2.(*CapMP)
	if !ok {
		return nil
	}

	dst := &CapMP{
		Proto: make(map[Asafi]bool),
	}
	for as, val := range c.Proto {
		if val && c2.Proto[as] {
			dst.Proto[as] = true
		}
	}
	return dst
}

func (c *CapMP) Marshal(dst []byte) []byte {
	for _, as := range c.Sorted() {
		dst = append(dst, byte(CAP_MP), 4)
		dst = msb.AppendUint32(dst, uint32(as))
	}
	return dst
}

func (c *CapMP) ToJSON(dst []byte) []byte {
	dst = append(dst, '[')
	for i, as := range c.Sorted() {
		if i > 0 {
			dst = append(dst, `,`...)
		}
		dst = as.ToJSON(dst)
	}
	return append(dst, ']')
}
