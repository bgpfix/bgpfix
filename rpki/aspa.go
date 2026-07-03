package rpki

import "slices"

// Hop authorization results (draft-ietf-sidrops-aspa-verification section 5)
const (
	HOP_NO_ATTESTATION = iota // CAS has no ASPA record
	HOP_PROVIDER              // PAS is listed as a provider of CAS
	HOP_NOT_PROVIDER          // CAS has an ASPA record that does not list PAS
)

// Hop checks ASPA authorization for a CAS->PAS hop.
// NB: provider lists must be sorted (see Cache.AddASPA).
func Hop(aspa ASPA, cas, pas uint32) int {
	provs, ok := aspa[cas]
	if !ok {
		return HOP_NO_ATTESTATION
	}
	if _, found := slices.BinarySearch(provs, pas); found {
		return HOP_PROVIDER
	}
	return HOP_NOT_PROVIDER
}

// VerifyPath verifies the flat AS_PATH against ASPA records (see Cache.ASPAs).
//
// path[0] is the most-recently-traversed AS (direct peer),
// path[N-1] is the origin AS. Returns ASPA_VALID, ASPA_UNKNOWN, or ASPA_INVALID.
// On ASPA_INVALID, failCAS and failPAS identify the hop where CAS has an ASPA
// record that does not list PAS as a provider. Both are 0 for other results.
//
// downstream=true when received from a provider or RS (downstream direction).
// downstream=false when received from a customer, peer, or RS-client (upstream).
//
// NB: does not check path[0] == neighbor AS (draft section 5.4/5.5 step 2).
// The caller must do that check, skipping it for RS peers (RFC 7947).
func VerifyPath(aspa ASPA, path []uint32, downstream bool) (result int, failCAS, failPAS uint32) {
	n := len(path)
	if n <= 1 {
		return ASPA_VALID, 0, 0
	}

	if !downstream {
		// upstream: every hop should go up (each AS sent to its provider)
		result = ASPA_VALID
		for i := 0; i < n-1; i++ {
			switch Hop(aspa, path[i+1], path[i]) {
			case HOP_NOT_PROVIDER:
				return ASPA_INVALID, path[i+1], path[i]
			case HOP_NO_ATTESTATION:
				result = ASPA_UNKNOWN
			}
		}
		return result, 0, 0
	}

	// downstream: find up-ramp from origin + down-ramp from peer.
	// Valid if the ramps leave at most one central pair uncovered.
	// That corresponds to the draft's rule that the two apexes may be
	// adjacent, i.e. separated by a single peer hop.
	//
	// max counts Provider and NoAttestation until first NotProvider;
	// min counts only leading Provider hops (stops at first NoAttestation).
	var upCAS, upPAS uint32
	maxUp, minUp := 0, 0
	exact := true
	for i := n - 2; i >= 0; i-- {
		auth := Hop(aspa, path[i+1], path[i])
		if auth == HOP_NOT_PROVIDER {
			upCAS, upPAS = path[i+1], path[i]
			break
		}
		maxUp++
		if auth == HOP_PROVIDER && exact {
			minUp++
		} else {
			exact = false
		}
	}

	var dnCAS, dnPAS uint32
	maxDown, minDown := 0, 0
	exact = true
	for i := 0; i < n-1; i++ {
		auth := Hop(aspa, path[i], path[i+1])
		if auth == HOP_NOT_PROVIDER {
			dnCAS, dnPAS = path[i], path[i+1]
			break
		}
		maxDown++
		if auth == HOP_PROVIDER && exact {
			minDown++
		} else {
			exact = false
		}
	}

	if maxUp+maxDown < n-2 {
		// NB: a >1-pair gap means both ramps hit NotProvider; report the
		// down-ramp failure (closer to the peer) if available.
		if dnCAS != 0 {
			return ASPA_INVALID, dnCAS, dnPAS
		}
		return ASPA_INVALID, upCAS, upPAS
	}
	if minUp+minDown < n-2 {
		return ASPA_UNKNOWN, 0, 0
	}
	return ASPA_VALID, 0, 0
}

// VerifyPath verifies path against the current cache snapshot.
// See the package-level VerifyPath.
func (c *Cache) VerifyPath(path []uint32, downstream bool) (result int, failCAS, failPAS uint32) {
	return VerifyPath(c.ASPAs(), path, downstream)
}
