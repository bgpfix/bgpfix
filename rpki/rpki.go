// Package rpki implements an RPKI data cache for BGP route validation.
//
// The Cache holds VRPs for Route Origin Validation (RFC 6811) and ASPA
// records for AS_PATH verification (draft-ietf-sidrops-aspa-verification).
// Writers stage changes in a pending set (AddVRP, AddASPA, Parse) and
// publish them atomically with Apply; readers validate against immutable
// snapshots without taking locks.
//
// Data can be fed from an RTR client (see the rtr package), or parsed
// from Routinator/rpki-client JSON or CSV files (see Parse).
package rpki

import "net/netip"

// VRP represents a single Validated ROA Payload
type VRP struct {
	MaxLen uint8
	ASN    uint32
}

// VRPs maps prefixes to lists of VRP entries
type VRPs = map[netip.Prefix][]VRP

// ASPA maps Customer ASN to its sorted list of Provider ASNs
type ASPA = map[uint32][]uint32

// ROV validation results (RFC 6811)
const (
	ROV_VALID     = iota // prefix+origin covered by a valid VRP
	ROV_INVALID          // prefix+origin conflicts with a VRP
	ROV_NOT_FOUND        // no VRP covers the prefix
)

// ASPA path verification results (draft-ietf-sidrops-aspa-verification)
const (
	ASPA_VALID   = iota // path is valley-free and fully attested
	ASPA_UNKNOWN        // insufficient attestation
	ASPA_INVALID        // proven route leak
)

// minimum VRP prefix lengths checked by ValidateOrigin
const (
	MIN_VRP_V4 = 8  // no VRPs shorter than /8 for IPv4
	MIN_VRP_V6 = 12 // no VRPs shorter than /12 for IPv6
)
