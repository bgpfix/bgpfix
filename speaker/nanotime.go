package speaker

import (
	_ "unsafe"
)

//go:noescape
//go:linkname nanotime runtime.nanotime
func nanotime() int64
