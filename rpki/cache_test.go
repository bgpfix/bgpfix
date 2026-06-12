package rpki

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

func TestAddVRPBasic(t *testing.T) {
	c := NewCache(nil)

	p4 := netip.MustParsePrefix("192.0.2.0/24")
	c.AddVRP(true, p4, 24, 65001)

	if len(c.next4) != 1 {
		t.Fatalf("expected 1 IPv4 VRP, got %d", len(c.next4))
	}
	if entries := c.next4[p4]; len(entries) != 1 {
		t.Fatalf("expected 1 entry for prefix, got %d", len(entries))
	}
	if entry := c.next4[p4][0]; entry.ASN != 65001 || entry.MaxLen != 24 {
		t.Errorf("wrong entry: ASN=%d MaxLen=%d", entry.ASN, entry.MaxLen)
	}

	p6 := netip.MustParsePrefix("2001:db8::/32")
	c.AddVRP(true, p6, 48, 65002)

	if len(c.next6) != 1 {
		t.Fatalf("expected 1 IPv6 VRP, got %d", len(c.next6))
	}
	if entries := c.next6[p6]; len(entries) != 1 {
		t.Fatalf("expected 1 entry for prefix, got %d", len(entries))
	}
}

func TestAddVRPDuplicates(t *testing.T) {
	c := NewCache(nil)

	p := netip.MustParsePrefix("192.0.2.0/24")
	c.AddVRP(true, p, 24, 65001)
	c.AddVRP(true, p, 24, 65001)

	if len(c.next4[p]) != 1 {
		t.Errorf("expected 1 entry (duplicate ignored), got %d", len(c.next4[p]))
	}
}

func TestAddVRPMultipleOrigins(t *testing.T) {
	c := NewCache(nil)

	p := netip.MustParsePrefix("192.0.2.0/24")

	// same prefix, different ASNs (MOAS scenario)
	c.AddVRP(true, p, 24, 65001)
	c.AddVRP(true, p, 24, 65002)
	c.AddVRP(true, p, 25, 65001) // same prefix, different maxLen

	if len(c.next4[p]) != 3 {
		t.Errorf("expected 3 entries, got %d", len(c.next4[p]))
	}
}

func TestAddVRPDelete(t *testing.T) {
	c := NewCache(nil)

	p := netip.MustParsePrefix("192.0.2.0/24")
	c.AddVRP(true, p, 24, 65001)
	c.AddVRP(true, p, 24, 65002)
	c.AddVRP(false, p, 24, 65001)

	entries := c.next4[p]
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry after delete, got %d", len(entries))
	}
	if entries[0].ASN != 65002 {
		t.Errorf("wrong entry remaining: ASN=%d", entries[0].ASN)
	}

	// deleting the last entry must drop the map key
	c.AddVRP(false, p, 24, 65002)
	if _, ok := c.next4[p]; ok {
		t.Errorf("expected key removed after deleting the last entry")
	}
}

func TestAddVRPDeleteNonExistent(t *testing.T) {
	c := NewCache(nil)

	p := netip.MustParsePrefix("192.0.2.0/24")
	c.AddVRP(true, p, 24, 65001)

	// delete non-existent entry (should be no-op)
	c.AddVRP(false, p, 24, 65999)

	if len(c.next4[p]) != 1 {
		t.Errorf("expected 1 entry (delete ignored), got %d", len(c.next4[p]))
	}
}

func TestAddVRPInvalidMaxLength(t *testing.T) {
	c := NewCache(nil)

	// maxLen=33 exceeds IPv4 max of 32 → should be rejected
	p4 := netip.MustParsePrefix("192.0.2.0/24")
	c.AddVRP(true, p4, 33, 65001)
	if len(c.next4[p4]) != 0 {
		t.Error("maxLen=33 should be rejected for IPv4")
	}

	// maxLen=129 exceeds IPv6 max of 128 → should be rejected
	p6 := netip.MustParsePrefix("2001:db8::/32")
	c.AddVRP(true, p6, 129, 65002)
	if len(c.next6[p6]) != 0 {
		t.Error("maxLen=129 should be rejected for IPv6")
	}

	// maxLen < prefix length → should be rejected
	c.AddVRP(true, p4, 20, 65001)
	if len(c.next4[p4]) != 0 {
		t.Error("maxLen < prefix length should be rejected")
	}

	// valid maxLen should be accepted
	c.AddVRP(true, p4, 32, 65001)
	if len(c.next4[p4]) != 1 {
		t.Error("maxLen=32 should be accepted for /24 IPv4")
	}
}

func TestAddVRPPrefixMasking(t *testing.T) {
	c := NewCache(nil)

	// add unmasked prefix (should be masked automatically)
	p := netip.MustParsePrefix("192.0.2.123/24")
	c.AddVRP(true, p, 24, 65001)

	masked := netip.MustParsePrefix("192.0.2.0/24")
	if _, exists := c.next4[masked]; !exists {
		t.Error("prefix was not properly masked")
	}
	if _, exists := c.next4[p]; exists && p != masked {
		t.Error("unmasked prefix was stored")
	}
}

func TestApply(t *testing.T) {
	c := NewCache(nil)

	c.AddVRP(true, netip.MustParsePrefix("192.0.2.0/24"), 24, 65001)
	c.AddVRP(true, netip.MustParsePrefix("2001:db8::/32"), 48, 65002)
	c.AddASPA(true, 65010, []uint32{65001})

	// not ready before first Apply
	select {
	case <-c.Ready():
		t.Fatal("cache ready before first Apply")
	default:
	}

	c.Apply()

	v4, v6 := c.VRPs()
	if len(v4) != 1 {
		t.Errorf("expected 1 IPv4 VRP in snapshot, got %d", len(v4))
	}
	if len(v6) != 1 {
		t.Errorf("expected 1 IPv6 VRP in snapshot, got %d", len(v6))
	}
	if len(c.ASPAs()) != 1 {
		t.Errorf("expected 1 ASPA in snapshot, got %d", len(c.ASPAs()))
	}

	// incremental updates after Apply must start from the published state
	// (the pending set is cloned lazily on first edit)
	c.AddVRP(true, netip.MustParsePrefix("198.51.100.0/24"), 24, 65003)
	if len(c.next4) != 2 || len(c.next6) != 1 || len(c.nextAspa) != 1 {
		t.Errorf("expected pending set cloned from snapshot, got v4=%d v6=%d aspa=%d",
			len(c.next4), len(c.next6), len(c.nextAspa))
	}

	// ready after Apply
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := c.WaitReady(ctx); err != nil {
		t.Errorf("WaitReady failed: %v", err)
	}
}

func TestApplyCloneIsolation(t *testing.T) {
	c := NewCache(nil)

	p := netip.MustParsePrefix("192.0.2.0/24")
	c.AddVRP(true, p, 24, 65001)
	c.Apply()

	// modifying the pending set must not affect the published snapshot
	c.AddVRP(true, p, 24, 65002)
	c.AddASPA(true, 65010, []uint32{65001})

	v4, _ := c.VRPs()
	if len(v4[p]) != 1 {
		t.Errorf("snapshot modified by pending update: %v", v4[p])
	}
	if len(c.ASPAs()) != 0 {
		t.Error("ASPA snapshot modified by pending update")
	}
}

func TestAddASPANormalization(t *testing.T) {
	c := NewCache(nil)

	// zeros removed, deduplicated, sorted
	c.AddASPA(true, 65001, []uint32{65300, 0, 65100, 65300, 65200})
	got := c.nextAspa[65001]
	want := []uint32{65100, 65200, 65300}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}

	// delete
	c.AddASPA(false, 65001, nil)
	if _, ok := c.nextAspa[65001]; ok {
		t.Error("ASPA record not deleted")
	}
}

func TestFlush(t *testing.T) {
	c := NewCache(nil)

	c.AddVRP(true, netip.MustParsePrefix("192.0.2.0/24"), 24, 65001)
	c.AddASPA(true, 65010, []uint32{65001})
	c.Flush()

	if len(c.next4) != 0 || len(c.nextAspa) != 0 {
		t.Error("Flush did not clear the pending set")
	}
}

func TestWaitReadyCancel(t *testing.T) {
	c := NewCache(nil)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := c.WaitReady(ctx); err == nil {
		t.Error("WaitReady should fail on cancelled context")
	}
}
