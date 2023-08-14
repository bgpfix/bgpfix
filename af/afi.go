// Package af implements AFI, SAFI, and combinations
package af

//go:generate go run github.com/dmarkham/enumer -type AFI -trimprefix AFI_
type AFI uint16

const (
	AFI_IPV4            AFI = 1
	AFI_IPV6            AFI = 2
	AFI_L2VPN           AFI = 25
	AFI_MPLS_SECTION    AFI = 26
	AFI_MPLS_LSP        AFI = 27
	AFI_MPLS_PSEUDOWIRE AFI = 28
	AFI_MT_IPV4         AFI = 29
	AFI_MT_IPV6         AFI = 30
	AFI_SFC             AFI = 31
	AFI_LS              AFI = 16388
	AFI_ROUTING_POLICY  AFI = 16398
	AFI_MPLS_NAMESPACES AFI = 16399
)
