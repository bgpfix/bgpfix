package rpki

import (
	"context"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/rs/zerolog"
)

// Cache is an RPKI data cache for ROV and ASPA validation.
//
// Writers stage changes in a pending set and publish them with Apply.
// Readers obtain immutable snapshots (VRPs, ASPAs) — the published maps
// must never be modified, so reads are lock-free.
type Cache struct {
	*zerolog.Logger

	mu       sync.Mutex // guards the pending set
	next4    VRPs       // pending IPv4 VRPs (nil = lazy clone of the snapshot)
	next6    VRPs       // pending IPv6 VRPs (nil = lazy clone of the snapshot)
	nextAspa ASPA       // pending ASPA records (nil = lazy clone of the snapshot)

	vrp4 atomic.Pointer[VRPs] // current IPv4 VRP snapshot
	vrp6 atomic.Pointer[VRPs] // current IPv6 VRP snapshot
	aspa atomic.Pointer[ASPA] // current ASPA snapshot

	ready chan struct{} // closed on first Apply
	once  sync.Once
}

// NewCache returns a new, empty Cache. If logger is nil, logging is disabled.
func NewCache(logger *zerolog.Logger) *Cache {
	c := &Cache{}
	if logger != nil {
		c.Logger = logger
	} else {
		l := zerolog.Nop()
		c.Logger = &l
	}
	c.vrp4.Store(new(VRPs))
	c.vrp6.Store(new(VRPs))
	c.aspa.Store(new(ASPA))
	c.ready = make(chan struct{})
	c.flush()
	return c
}

// Flush drops all pending changes, restarting from an empty pending set.
// The current snapshot is not affected until the next Apply.
func (c *Cache) Flush() {
	c.mu.Lock()
	c.flush()
	c.mu.Unlock()
}

func (c *Cache) flush() {
	c.next4 = make(VRPs)
	c.next6 = make(VRPs)
	c.nextAspa = make(ASPA)
}

// ensureNext materializes the pending set, with c.mu held.
// NB: cloning the snapshot is deferred to the first edit after Apply, so
// sources that rebuild from scratch (Flush+Parse+Apply) never pay for it.
func (c *Cache) ensureNext() {
	if c.next4 != nil {
		return
	}
	c.next4 = cloneVRPs(*c.vrp4.Load())
	c.next6 = cloneVRPs(*c.vrp6.Load())
	aspa := *c.aspa.Load()
	c.nextAspa = make(ASPA, len(aspa))
	for cas, provs := range aspa {
		c.nextAspa[cas] = slices.Clone(provs)
	}
}

func cloneVRPs(src VRPs) VRPs {
	dst := make(VRPs, len(src))
	for p, entries := range src {
		if len(entries) > 0 {
			dst[p] = slices.Clone(entries)
		}
	}
	return dst
}

// AddVRP adds (add=true) or removes (add=false) a VRP in the pending set.
// Entries with invalid maxLen are dropped with a warning.
func (c *Cache) AddVRP(add bool, prefix netip.Prefix, maxLen uint8, asn uint32) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.addVRP(add, prefix, maxLen, asn)
}

// addVRP is AddVRP with c.mu held.
func (c *Cache) addVRP(add bool, prefix netip.Prefix, maxLen uint8, asn uint32) {
	p := prefix.Masked()
	is6 := p.Addr().Is6()
	maxBits := 32
	if is6 {
		maxBits = 128
	}
	if ml := int(maxLen); ml < p.Bits() || ml > maxBits {
		c.Warn().Str("prefix", prefix.String()).Int("maxLength", ml).Msg("invalid maxLength, skipping")
		return
	}
	entry := VRP{MaxLen: maxLen, ASN: asn}

	c.ensureNext()
	next := c.next4
	if is6 {
		next = c.next6
	}
	i := slices.Index(next[p], entry)
	if add {
		if i < 0 {
			next[p] = append(next[p], entry)
		}
	} else {
		if i >= 0 {
			next[p] = slices.Delete(next[p], i, i+1)
		}
	}
}

// AddASPA adds (add=true) or removes (add=false) an ASPA record in the
// pending set. Providers are normalized: zeros removed, deduplicated, sorted.
func (c *Cache) AddASPA(add bool, cas uint32, providers []uint32) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.addASPA(add, cas, providers)
}

// addASPA is AddASPA with c.mu held.
func (c *Cache) addASPA(add bool, cas uint32, providers []uint32) {
	c.ensureNext()
	if add {
		// normalize: remove zeros, deduplicate, sort for BinarySearch
		norm := make([]uint32, 0, len(providers))
		for _, p := range providers {
			if p != 0 {
				norm = append(norm, p)
			}
		}
		slices.Sort(norm)
		norm = slices.Compact(norm)
		c.nextAspa[cas] = norm
	} else {
		delete(c.nextAspa, cas)
	}
}

// Apply atomically publishes the pending set as the current snapshot.
// The next pending set starts as a lazy clone of the snapshot, so that
// subsequent incremental updates continue from the published state.
func (c *Cache) Apply() {
	c.mu.Lock()
	if c.next4 != nil {
		v4, v6, aspa := c.next4, c.next6, c.nextAspa
		c.vrp4.Store(&v4)
		c.vrp6.Store(&v6)
		c.aspa.Store(&aspa)

		// NB: published maps are immutable; cloned back in ensureNext
		c.next4, c.next6, c.nextAspa = nil, nil, nil
	}
	c.mu.Unlock()

	vrps4, vrps6, aspas := c.Sizes()
	c.Info().Int("vrps4", vrps4).Int("vrps6", vrps6).Int("aspas", aspas).Msg("RPKI cache updated")
	c.once.Do(func() { close(c.ready) })
}

// Ready returns a channel that is closed after the first Apply.
func (c *Cache) Ready() <-chan struct{} {
	return c.ready
}

// WaitReady blocks until the cache has data (first Apply), or ctx is done.
func (c *Cache) WaitReady(ctx context.Context) error {
	select {
	case <-c.ready:
		return nil
	case <-ctx.Done():
		return context.Cause(ctx)
	}
}

// VRPs returns the current IPv4 and IPv6 VRP snapshots.
// The returned maps are immutable and must not be modified.
func (c *Cache) VRPs() (v4, v6 VRPs) {
	return *c.vrp4.Load(), *c.vrp6.Load()
}

// ASPAs returns the current ASPA snapshot.
// The returned map is immutable and must not be modified.
func (c *Cache) ASPAs() ASPA {
	return *c.aspa.Load()
}

// Sizes returns the number of entries in the current snapshots.
func (c *Cache) Sizes() (vrps4, vrps6, aspas int) {
	return len(*c.vrp4.Load()), len(*c.vrp6.Load()), len(*c.aspa.Load())
}
