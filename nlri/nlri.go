package nlri

import "net/netip"

type NLRI struct {
	PathID uint32
	Prefix netip.Prefix
}
