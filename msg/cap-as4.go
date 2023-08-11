package msg

import (
	"strconv"
)

// CAP_AS4 rfc6793
type CapAS4 struct {
	ASN uint32
}

func NewCapAS4(cc CapCode) Cap {
	return &CapAS4{}
}

func (c *CapAS4) Unmarshal(buf []byte, caps Caps) error {
	if len(buf) != 4 {
		return ErrLength
	}

	c.ASN = msb.Uint32(buf)
	return nil
}

func (c *CapAS4) Common(cap2 Cap) Cap {
	return nil
}

func (c *CapAS4) Marshal(dst []byte) []byte {
	dst = append(dst, byte(CAP_AS4), 4)
	dst = msb.AppendUint32(dst, c.ASN)
	return dst
}

func (c *CapAS4) ToJSON(dst []byte) []byte {
	return strconv.AppendUint(dst, uint64(c.ASN), 10)
}
