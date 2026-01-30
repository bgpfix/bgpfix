package caps

import (
	"github.com/bgpfix/bgpfix/json"
)

// Role values per RFC 9234
const (
	ROLE_PROVIDER  byte = 0
	ROLE_RS        byte = 1 // Route Server
	ROLE_RS_CLIENT byte = 2
	ROLE_CUSTOMER  byte = 3
	ROLE_PEER      byte = 4
)

// Role implements CAP_ROLE per RFC 9234
type Role struct {
	Role byte
}

func NewRole(cc Code) Cap {
	return &Role{}
}

func (c *Role) Unmarshal(buf []byte, caps Caps) error {
	if len(buf) != 1 {
		return ErrLength
	}
	c.Role = buf[0]
	return nil
}

func (c *Role) Intersect(cap2 Cap) Cap {
	return nil
}

func (c *Role) Marshal(dst []byte) []byte {
	dst = append(dst, byte(CAP_ROLE), 1)
	dst = append(dst, c.Role)
	return dst
}

func (c *Role) ToJSON(dst []byte) []byte {
	switch c.Role {
	case ROLE_PROVIDER:
		return append(dst, `"PROVIDER"`...)
	case ROLE_RS:
		return append(dst, `"RS"`...)
	case ROLE_RS_CLIENT:
		return append(dst, `"RS-CLIENT"`...)
	case ROLE_CUSTOMER:
		return append(dst, `"CUSTOMER"`...)
	case ROLE_PEER:
		return append(dst, `"PEER"`...)
	default:
		return json.Byte(dst, c.Role)
	}
}

func (c *Role) FromJSON(src []byte) error {
	src = json.Q(src)
	switch json.S(src) {
	case "PROVIDER":
		c.Role = ROLE_PROVIDER
	case "RS":
		c.Role = ROLE_RS
	case "RS-CLIENT":
		c.Role = ROLE_RS_CLIENT
	case "CUSTOMER":
		c.Role = ROLE_CUSTOMER
	case "PEER":
		c.Role = ROLE_PEER
	default:
		val, err := json.UnByte(src)
		if err != nil {
			return err
		}
		c.Role = val
	}
	return nil
}
