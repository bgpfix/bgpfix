package caps

import (
	"github.com/bgpfix/bgpfix/binary"
)

var msb = binary.Msb

const hextable = "0123456789abcdef"

func jsonHex(dst []byte, src []byte) []byte {
	if src == nil {
		return append(dst, `null`...)
	} else if len(src) == 0 {
		return append(dst, `""`...)
	}

	dst = append(dst, `"0x`...)
	for _, v := range src {
		dst = append(dst, hextable[v>>4], hextable[v&0x0f])
	}
	return append(dst, '"')
}
