package af

import (
	"unsafe"

	"github.com/bgpfix/bgpfix/binary"
)

var msb = binary.Msb

// bsu returns string from byte slice, unquoting if necessary
func bsu(buf []byte) string {
	if l := len(buf); l > 1 && buf[0] == '"' && buf[l-1] == '"' {
		buf = buf[1 : l-1]
	}
	return *(*string)(unsafe.Pointer(&buf))
}
