package caps

import (
	"bytes"

	"github.com/bgpfix/bgpfix/json"
)

// Raw represents any BGP capability as raw bytes
type Raw struct {
	Code
	Raw [][]byte
}

func NewRaw(cc Code) Cap {
	return &Raw{Code: cc}
}

func (c *Raw) Unmarshal(buf []byte, caps Caps) error {
	if len(buf) > 0 {
		c.Raw = append(c.Raw, buf)
	}
	return nil
}

func (c *Raw) Intersect(cap2 Cap) Cap {
	c2, ok := cap2.(*Raw)
	if !ok || c.Code != c2.Code {
		return nil
	} else if len(c.Raw) == 0 && len(c2.Raw) == 0 {
		return nil
	}

	dst := &Raw{Code: c.Code}
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

func (c *Raw) ToJSON(dst []byte) []byte {
	switch len(c.Raw) {
	case 0:
		dst = append(dst, json.True...)
	case 1:
		if len(c.Raw[0]) == 0 {
			return append(dst, json.True...)
		} else {
			dst = json.Hex(dst, c.Raw[0])
		}
	default:
		dst = append(dst, `[`...)
		for i := range c.Raw {
			if i > 0 {
				dst = append(dst, ',')
			}
			dst = json.Hex(dst, c.Raw[i])
		}
		dst = append(dst, `]`...)
	}
	return dst
}

func (c *Raw) FromJSON(src []byte) error {
	c.Raw = nil

	// just "true"?
	if bytes.Equal(json.Q(src), json.True) {
		return nil
	}

	// app_hex parses val as hex and apppends to c.Raw
	app_hex := func(val []byte) error {
		raw, err := json.UnHex(val, nil)
		if err != nil {
			return err
		} else {
			c.Raw = append(c.Raw, raw)
			return nil
		}
	}

	// array of hex values?
	if src[0] == '[' {
		return json.ArrayEach(src, func(key int, val []byte, typ json.Type) error {
			return app_hex(val)
		})
	}

	// a single hex value?
	return app_hex(src)
}

func (c *Raw) Marshal(dst []byte) []byte {
	// special case
	if len(c.Raw) == 0 {
		return append(dst, byte(c.Code), 0)
	}

	for _, buf := range c.Raw {
		l := len(buf)
		if l > 255 {
			continue // should not happen
		}
		dst = append(dst, byte(c.Code), byte(l))
		dst = append(dst, buf[:l]...)
	}
	return dst
}
