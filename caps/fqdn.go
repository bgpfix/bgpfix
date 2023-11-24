package caps

import (
	"github.com/bgpfix/bgpfix/json"
)

// Fqdn implements CAP_FQDN draft-walton-bgp-hostname-capability-00
type Fqdn struct {
	Host   []byte
	Domain []byte
}

func NewFqdn(cc Code) Cap {
	return &Fqdn{}
}

func (c *Fqdn) Unmarshal(buf []byte, caps Caps) error {
	if len(buf) < 2 {
		return ErrLength
	}

	// hostname length (1) + hostname (variable)
	l, buf := int(buf[0]), buf[1:]
	if len(buf) < l {
		return ErrLength
	}
	c.Host, buf = buf[:l], buf[l:]

	// domain name length (1) + domain (variable)
	l, buf = int(buf[0]), buf[1:]
	if len(buf) < l {
		return ErrLength
	}
	c.Domain = buf[:l]

	return nil
}

func (c *Fqdn) Intersect(cap2 Cap) Cap {
	return nil
}

func (c *Fqdn) Marshal(dst []byte) []byte {
	// total length
	total := len(c.Host) + len(c.Domain) + 2
	if total > 0xff {
		return nil // invalid, skip
	}

	dst = append(dst, byte(CAP_FQDN), byte(total))

	dst = append(dst, byte(len(c.Host)))
	dst = append(dst, c.Host...)

	dst = append(dst, byte(len(c.Domain)))
	dst = append(dst, c.Domain...)

	return dst
}

func (c *Fqdn) ToJSON(dst []byte) []byte {
	dst = append(dst, `{"host":"`...)
	dst = json.Ascii(dst, c.Host)
	dst = append(dst, `"`...)

	if len(c.Domain) > 0 {
		dst = append(dst, `","domain":"`...)
		dst = json.Ascii(dst, c.Domain)
		dst = append(dst, `"`...)
	}

	return append(dst, '}')
}

func (c *Fqdn) FromJSON(src []byte) (err error) {
	return json.ObjectEach(src, func(key string, val []byte, typ json.Type) (err error) {
		switch key {
		case "host":
			c.Host = append(c.Host[:0], val...)
		case "domain":
			c.Domain = append(c.Domain[:0], val...)
		}
		return err
	})
}
