package attrs

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func codes(ats *Attrs) (cs []Code) {
	ats.Each(func(i int, ac Code, at Attr) { cs = append(cs, ac) })
	return
}

func TestAttrs_Set(t *testing.T) {
	var ats Attrs
	require.Nil(t, ats.Get(ATTR_ORIGIN))
	require.False(t, ats.Has(ATTR_ORIGIN))

	// Each is ordered by code, whatever the insertion order
	ats.Use(ATTR_COMMUNITY)
	ats.Use(ATTR_ORIGIN)
	ats.Use(ATTR_NEXTHOP)
	require.Equal(t, 3, ats.Len())
	require.Equal(t, []Code{ATTR_ORIGIN, ATTR_NEXTHOP, ATTR_COMMUNITY}, codes(&ats))

	// Use is idempotent
	at := ats.Use(ATTR_ORIGIN)
	require.Same(t, at, ats.Use(ATTR_ORIGIN))
	require.Equal(t, 3, ats.Len())

	// Drop, Set(nil), and Filter
	ats.Drop(ATTR_NEXTHOP)
	ats.Set(ATTR_MED, nil)
	require.Equal(t, []Code{ATTR_ORIGIN, ATTR_COMMUNITY}, codes(&ats))
	ats.Use(ATTR_ASPATH)
	ats.Filter(ATTR_ASPATH, ATTR_COMMUNITY)
	require.Equal(t, []Code{ATTR_ASPATH, ATTR_COMMUNITY}, codes(&ats))

	// Reset keeps instances for re-use
	cm := ats.Get(ATTR_COMMUNITY)
	ats.Reset()
	require.Equal(t, 0, ats.Len())
	require.Nil(t, ats.Get(ATTR_COMMUNITY))
	require.Same(t, cm, ats.Use(ATTR_COMMUNITY))

	// Set replaces; free instances stay unique by code and do not pile up
	for range 10 {
		ats.Set(ATTR_ORIGIN, NewAttr(ATTR_ORIGIN))
		ats.Reset()
	}
	seen := map[Code]bool{}
	for _, e := range ats.free {
		require.False(t, seen[e.code], "duplicate free %s", e.code)
		seen[e.code] = true
	}
}
