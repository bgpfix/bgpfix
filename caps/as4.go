package caps

import (
	"github.com/bgpfix/bgpfix/json"
)

// AS4 implements CAP_AS4 rfc6793
type AS4 struct {
	ASN uint32
}

func NewAS4(cc Code) Cap {
	return &AS4{}
}

func (c *AS4) Unmarshal(buf []byte, caps Caps) error {
	if len(buf) != 4 {
		return ErrLength
	}

	c.ASN = msb.Uint32(buf)
	return nil
}

func (c *AS4) Intersect(cap2 Cap) Cap {
	return nil
}

func (c *AS4) Marshal(dst []byte) []byte {
	dst = append(dst, byte(CAP_AS4), 4)
	dst = msb.AppendUint32(dst, c.ASN)
	return dst
}

func (c *AS4) ToJSON(dst []byte) []byte {
	return json.Uint32(dst, c.ASN)
}

func (c *AS4) FromJSON(src []byte) (err error) {
	c.ASN, err = json.UnUint32(src)
	return err
}
