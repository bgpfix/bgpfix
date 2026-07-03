package rpki

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// --- Hop tests ---

func TestHop_Provider(t *testing.T) {
	aspa := ASPA{
		65001: {65100, 65200},
	}
	require.Equal(t, HOP_PROVIDER, Hop(aspa, 65001, 65100))
	require.Equal(t, HOP_PROVIDER, Hop(aspa, 65001, 65200))
}

func TestHop_NotProvider(t *testing.T) {
	aspa := ASPA{
		65001: {65100, 65200},
	}
	require.Equal(t, HOP_NOT_PROVIDER, Hop(aspa, 65001, 65999))
}

func TestHop_NoAttestation(t *testing.T) {
	aspa := ASPA{
		65001: {65100},
	}
	// CAS 65002 has no ASPA record
	require.Equal(t, HOP_NO_ATTESTATION, Hop(aspa, 65002, 65100))
}

func TestHop_EmptyProviderList(t *testing.T) {
	aspa := ASPA{
		65001: {}, // has record but no providers
	}
	require.Equal(t, HOP_NOT_PROVIDER, Hop(aspa, 65001, 65100))
}

// --- VerifyPath upstream tests ---

func TestVerifyPath_Upstream_Valid(t *testing.T) {
	// path: 65001 -> 65002 -> 65003 (origin)
	// 65003 says 65002 is my provider, 65002 says 65001 is my provider
	aspa := ASPA{
		65003: {65002},
		65002: {65001},
	}
	path := []uint32{65001, 65002, 65003}
	result, cas, pas := VerifyPath(aspa, path, false)
	require.Equal(t, ASPA_VALID, result)
	require.Zero(t, cas)
	require.Zero(t, pas)
}

func TestVerifyPath_Upstream_Invalid(t *testing.T) {
	// 65003 says 65002 is NOT its provider (65099 is)
	aspa := ASPA{
		65003: {65099},
		65002: {65001},
	}
	path := []uint32{65001, 65002, 65003}
	result, cas, pas := VerifyPath(aspa, path, false)
	require.Equal(t, ASPA_INVALID, result)
	require.Equal(t, uint32(65003), cas) // 65003 has ASPA but doesn't list 65002
	require.Equal(t, uint32(65002), pas)
}

func TestVerifyPath_Upstream_Unknown(t *testing.T) {
	// 65002 has no ASPA record -> unknown
	aspa := ASPA{
		65003: {65002},
	}
	path := []uint32{65001, 65002, 65003}
	result, cas, pas := VerifyPath(aspa, path, false)
	require.Equal(t, ASPA_UNKNOWN, result)
	require.Zero(t, cas)
	require.Zero(t, pas)
}

func TestVerifyPath_Upstream_SingleHop(t *testing.T) {
	aspa := ASPA{}
	result, cas, pas := VerifyPath(aspa, []uint32{65001}, false)
	require.Equal(t, ASPA_VALID, result)
	require.Zero(t, cas)
	require.Zero(t, pas)
}

func TestVerifyPath_Upstream_TwoHop_Valid(t *testing.T) {
	// path: 65001 -> 65002. 65002 says 65001 is provider.
	aspa := ASPA{
		65002: {65001},
	}
	result, _, _ := VerifyPath(aspa, []uint32{65001, 65002}, false)
	require.Equal(t, ASPA_VALID, result)
}

func TestVerifyPath_Upstream_TwoHop_Invalid(t *testing.T) {
	// path: 65001 -> 65002. 65002 says 65099 is provider, not 65001.
	aspa := ASPA{
		65002: {65099},
	}
	result, cas, pas := VerifyPath(aspa, []uint32{65001, 65002}, false)
	require.Equal(t, ASPA_INVALID, result)
	require.Equal(t, uint32(65002), cas)
	require.Equal(t, uint32(65001), pas)
}

// --- VerifyPath downstream tests ---

func TestVerifyPath_Downstream_ValleyFree(t *testing.T) {
	// path: 65001 -> 65002 -> 65003 (origin)
	// valley-free: origin goes up to 65002, then 65002 goes down to 65001
	// up-ramp: 65003->65002 (65003 says 65002 is provider)
	// down-ramp: 65001->65002 (65001 says 65002 is provider)
	aspa := ASPA{
		65003: {65002},
		65001: {65002},
	}
	path := []uint32{65001, 65002, 65003}
	result, cas, pas := VerifyPath(aspa, path, true)
	require.Equal(t, ASPA_VALID, result)
	require.Zero(t, cas)
	require.Zero(t, pas)
}

func TestVerifyPath_Downstream_NotValleyFree(t *testing.T) {
	// path: 65001 -> 65002 -> 65003 (origin)
	// all ASes have ASPA records but the path is not valley-free:
	// up-ramp: Hop(65003, 65002) -> 65003 says 65099 -> NOT_PROVIDER -> break (maxUp=0, upCAS=65003, upPAS=65002)
	// down-ramp: Hop(65001, 65002) -> 65001 says 65099 -> NOT_PROVIDER -> break (maxDown=0, dnCAS=65001, dnPAS=65002)
	// maxUp + maxDown = 0 < n-2 = 1 -> invalid; down-ramp failure preferred (dnCAS != 0)
	aspa := ASPA{
		65003: {65099},
		65002: {65099},
		65001: {65099},
	}
	path := []uint32{65001, 65002, 65003}
	result, cas, pas := VerifyPath(aspa, path, true)
	require.Equal(t, ASPA_INVALID, result)
	require.Equal(t, uint32(65001), cas) // down-ramp: 65001 doesn't list 65002 as provider
	require.Equal(t, uint32(65002), pas)
}

func TestVerifyPath_Downstream_ShortPathCanStillBeValid(t *testing.T) {
	// path: 65001 -> 65002 -> 65003 (origin)
	// 65003 says 65002 is provider, while 65001 has no ASPA.
	// The draft still considers this valid: the up-ramp can extend all the way
	// to the neighbor side, and the down-ramp can degenerate to the neighbor AS.
	aspa := ASPA{
		65003: {65002},
	}
	path := []uint32{65001, 65002, 65003}
	result, _, _ := VerifyPath(aspa, path, true)
	require.Equal(t, ASPA_VALID, result)
}

func TestVerifyPath_Downstream_LongValleyFree(t *testing.T) {
	// 4-hop valley-free path: 65001 -> 65002 -> 65003 -> 65004 (origin)
	// origin goes up: 65004->65003 (provider), 65003->65002 (provider)
	// peer goes down: 65001->65002 (provider)
	aspa := ASPA{
		65004: {65003},
		65003: {65002},
		65001: {65002},
	}
	path := []uint32{65001, 65002, 65003, 65004}
	result, _, _ := VerifyPath(aspa, path, true)
	require.Equal(t, ASPA_VALID, result)
}

func TestVerifyPath_Downstream_PeerPeering(t *testing.T) {
	// 3-hop with peering at top: 65001 -> 65002 -> 65003 (origin)
	// The draft allows one central hop between the up-ramp apex and down-ramp
	// apex. Here, 65002-65003 is that peer hop, so the path is still valid.
	aspa := ASPA{
		65003: {65099}, // 65003's provider is 65099, not 65002
		65002: {65099}, // 65002 has record (needed for definitive NotProvider results)
		65001: {65002},
	}
	path := []uint32{65001, 65002, 65003}
	result, _, _ := VerifyPath(aspa, path, true)
	require.Equal(t, ASPA_VALID, result)
}

func TestVerifyPath_Downstream_Tier1PeeringIsUnknown(t *testing.T) {
	// 4-hop path with a single Tier1-Tier1 peer hop in the middle:
	// 65001 -> 65002 -> 65003 -> 65004 (origin)
	// 65002 and 65003 publish AS0 ASPAs (represented here as empty provider
	// lists), so their mutual hop is a definitive NotProvider. The outer hops
	// are unattested, so the path is deployable today but only UNKNOWN.
	aspa := ASPA{
		65002: {},
		65003: {},
	}
	path := []uint32{65001, 65002, 65003, 65004}
	result, _, _ := VerifyPath(aspa, path, true)
	require.Equal(t, ASPA_UNKNOWN, result)
}

func TestVerifyPath_EmptyASPA(t *testing.T) {
	// no ASPA data -> all hops are NoAttestation -> unknown
	aspa := ASPA{}
	path := []uint32{65001, 65002, 65003}
	result1, cas1, _ := VerifyPath(aspa, path, false)
	require.Equal(t, ASPA_UNKNOWN, result1)
	require.Zero(t, cas1)
	result2, cas2, _ := VerifyPath(aspa, path, true)
	require.Equal(t, ASPA_UNKNOWN, result2)
	require.Zero(t, cas2)
}

// --- VerifyPath hop tracking tests ---

func TestVerifyPath_Upstream_HopAtFirstFail(t *testing.T) {
	// path: [65001, 65002, 65003]; 65002 has ASPA but doesn't list 65001 as provider
	// first check: Hop(65002, 65001) -> NOT_PROVIDER -> INVALID, CAS=65002, PAS=65001
	aspa := ASPA{
		65002: {65099},
		65003: {65002},
	}
	path := []uint32{65001, 65002, 65003}
	result, cas, pas := VerifyPath(aspa, path, false)
	require.Equal(t, ASPA_INVALID, result)
	require.Equal(t, uint32(65002), cas)
	require.Equal(t, uint32(65001), pas)
}

func TestVerifyPath_Upstream_HopAtSecondFail(t *testing.T) {
	// path: [65001, 65002, 65003]; first hop OK, second fails
	// Hop(65002, 65001) -> PROVIDER OK
	// Hop(65003, 65002) -> NOT_PROVIDER -> INVALID, CAS=65003, PAS=65002
	aspa := ASPA{
		65002: {65001},
		65003: {65099},
	}
	path := []uint32{65001, 65002, 65003}
	result, cas, pas := VerifyPath(aspa, path, false)
	require.Equal(t, ASPA_INVALID, result)
	require.Equal(t, uint32(65003), cas)
	require.Equal(t, uint32(65002), pas)
}

func TestVerifyPath_Downstream_HopPrefersDnRamp(t *testing.T) {
	// path: [65001, 65002, 65003, 65004]
	// down-ramp: Hop(65001, 65002) -> 65001 says 65099, not 65002 -> NOT_PROVIDER (dnCAS=65001, dnPAS=65002)
	// up-ramp: Hop(65004, 65003) -> 65004 says 65099, not 65003 -> NOT_PROVIDER (upCAS=65004, upPAS=65003)
	// INVALID: prefer down-ramp (dnCAS != 0)
	aspa := ASPA{
		65001: {65099},
		65002: {65099},
		65003: {65099},
		65004: {65099},
	}
	path := []uint32{65001, 65002, 65003, 65004}
	result, cas, pas := VerifyPath(aspa, path, true)
	require.Equal(t, ASPA_INVALID, result)
	require.Equal(t, uint32(65001), cas) // down-ramp failure preferred
	require.Equal(t, uint32(65002), pas)
}

// --- Cache.VerifyPath ---

func TestCacheVerifyPath(t *testing.T) {
	c := NewCache(nil)
	c.AddASPA(true, 65003, []uint32{65002})
	c.AddASPA(true, 65002, []uint32{65001})
	c.Apply()

	result, _, _ := c.VerifyPath([]uint32{65001, 65002, 65003}, false)
	require.Equal(t, ASPA_VALID, result)
}
