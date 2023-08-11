package msg

import "bytes"

// CapRaw represents any BGP capability as raw bytes
type CapRaw struct {
	CapCode
	Raw [][]byte
}

func NewCapRaw(cc CapCode) Cap {
	return &CapRaw{CapCode: cc}
}

func (c *CapRaw) Unmarshal(buf []byte, caps Caps) error {
	if len(buf) > 0 {
		c.Raw = append(c.Raw, buf)
	}
	return nil
}

func (c *CapRaw) Common(cap2 Cap) Cap {
	c2, ok := cap2.(*CapRaw)
	if !ok || c.CapCode != c2.CapCode {
		return nil
	} else if len(c.Raw) == 0 && len(c2.Raw) == 0 {
		return nil
	}

	dst := &CapRaw{CapCode: c.CapCode}
	for _, val := range c.Raw {
		for _, val2 := range c2.Raw {
			if bytes.Equal(val, val2) {
				v := append([]byte(nil), val...) // copy
				dst.Raw = append(dst.Raw, v)
			}
		}
	}
	return dst
}

func (c *CapRaw) ToJSON(dst []byte) []byte {
	switch len(c.Raw) {
	case 0:
		dst = append(dst, `true`...)
	case 1:
		if len(c.Raw[0]) == 0 {
			return append(dst, `true`...)
		} else {
			dst = jsonHex(dst, c.Raw[0])
		}
	default:
		dst = append(dst, `[`...)
		for i := range c.Raw {
			if i > 0 {
				dst = append(dst, ',')
			}
			dst = jsonHex(dst, c.Raw[i])
		}
		dst = append(dst, `]`...)
	}
	return dst
}

func (c *CapRaw) Marshal(dst []byte) []byte {
	// special case
	if len(c.Raw) == 0 {
		return append(dst, byte(c.CapCode), 0)
	}

	for _, buf := range c.Raw {
		l := len(buf)
		if l > 255 {
			continue // should not happen
		}
		dst = append(dst, byte(c.CapCode), byte(l))
		dst = append(dst, buf[:l]...)
	}
	return dst
}
