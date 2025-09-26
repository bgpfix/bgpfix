package exa

import (
	"net/netip"
	"testing"

	"github.com/bgpfix/bgpfix/msg"
	"github.com/bgpfix/bgpfix/nlri"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLineRoundTrip(t *testing.T) {
	testCases := []struct {
		name string
		line string
	}{
		{
			name: "basic announce",
			line: "announce route 10.0.0.0/24 next-hop 192.168.1.1",
		},
		{
			name: "basic withdraw",
			line: "withdraw route 10.0.0.0/24",
		},
		{
			name: "announce with origin",
			line: "announce route 192.168.1.0/24 next-hop 10.0.0.1 origin IGP",
		},
		{
			name: "announce with as-path",
			line: "announce route 172.16.0.0/16 next-hop 192.168.1.1 as-path [ 65001 65002 65003 ]",
		},
		{
			name: "announce with med",
			line: "announce route 10.1.0.0/16 next-hop 10.0.0.1 med 100",
		},
		{
			name: "announce with local-preference",
			line: "announce route 10.2.0.0/16 next-hop 10.0.0.1 local-preference 200",
		},
		{
			name: "announce with no-export community",
			line: "announce route 10.0.0.0/24 next-hop 192.168.1.1 community [ no-export ]",
		},
		{
			name: "announce with numeric community",
			line: "announce route 10.0.0.0/24 next-hop 192.168.1.1 community [ 666:666 ]",
		},
		{
			name: "announce with multiple communities",
			line: "announce route 10.0.0.0/24 next-hop 192.168.1.1 community [ no-export no-advertise 123:456 ]",
		},
		{
			name: "announce with all well-known communities",
			line: "announce route 10.0.0.0/24 next-hop 192.168.1.1 community [ no-export no-advertise no-export-subconfed no-peer blackhole ]",
		},
		{
			name: "announce with underscores in community names",
			line: "announce route 10.0.0.0/24 next-hop 192.168.1.1 community [ no_export no_advertise ]",
		},
		{
			name: "complex announce with all attributes",
			line: "announce route 172.20.0.0/16 next-hop 192.168.10.1 origin IGP as-path [ 65100 65200 ] med 50 local-preference 150 community [ 100:200 no-export ]",
		},
		{
			name: "withdraw with next-hop",
			line: "withdraw route 10.0.0.0/24",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Parse the src src
			src, err := NewExaLine(tc.line)
			require.NoError(t, err, "Failed to parse original line: %s", tc.line)

			// Convert to bgpfix Msg
			m := msg.NewMsg()
			err = src.ToMsg(m)
			require.NoError(t, err, "Failed to convert Exa to Msg")

			// Convert back to Exa using iterator
			dst := NewExa()
			count := 0
			for range dst.IterMsg(m) {
				count++
				// Should only have one result for single prefix
				assert.Equal(t, 1, count, "Expected exactly one result from iterator")

				// Compare the essential fields
				assert.Equal(t, src.Action, dst.Action, "Action mismatch")
				assert.Equal(t, src.Prefix, dst.Prefix, "Prefix mismatch")

				// For withdrawals, attributes are not preserved, so only check for announcements
				if src.Action == "announce" {
					assert.Equal(t, src.NextHop, dst.NextHop, "NextHop mismatch")
					assert.Equal(t, src.Origin, dst.Origin, "Origin mismatch")
					assert.Equal(t, src.ASPath, dst.ASPath, "ASPath mismatch")
					assert.Equal(t, src.MED, dst.MED, "MED mismatch")
					assert.Equal(t, src.LocalPref, dst.LocalPref, "LocalPref mismatch")
					assert.Equal(t, src.Community, dst.Community, "Community mismatch")
				}
			}

			assert.Equal(t, 1, count, "Expected exactly one result from iterator")
		})
	}
}

func TestLineParsing(t *testing.T) {
	testCases := []struct {
		name   string
		line   string
		expect Exa
		fail   bool
	}{
		{
			name: "basic announce",
			line: "announce route 10.0.0.1/24 next-hop self",
			expect: Exa{
				Action:  "announce",
				Prefix:  "10.0.0.1/24",
				NextHop: "self",
			},
		},
		{
			name: "basic withdraw",
			line: "withdraw route 192.168.1.0/24",
			expect: Exa{
				Action: "withdraw",
				Prefix: "192.168.1.0/24",
			},
		},
		{
			name: "invalid withdraw",
			line: "withdraw route 192.168.1.0/24 as-path [ 65001 ]",
			fail: true,
		},
		{
			name: "announce with origin",
			line: "announce route 10.0.0.0/8 next-hop 192.168.1.1 origin IGP",
			expect: Exa{
				Action:  "announce",
				Prefix:  "10.0.0.0/8",
				NextHop: "192.168.1.1",
				Origin:  "IGP",
			},
		},
		{
			name: "announce with as-path",
			line: "announce route 172.16.0.0/12 next-hop 10.0.0.1 as-path [ 65001 65002 ]",
			expect: Exa{
				Action:  "announce",
				Prefix:  "172.16.0.0/12",
				NextHop: "10.0.0.1",
				ASPath:  []uint32{65001, 65002},
			},
		},
		{
			name: "announce with med",
			line: "announce route 10.1.0.0/16 next-hop 10.0.0.1 med 100",
			expect: Exa{
				Action:  "announce",
				Prefix:  "10.1.0.0/16",
				NextHop: "10.0.0.1",
				MED:     uint32Ptr(100),
			},
		},
		{
			name: "announce with local-preference",
			line: "announce route 10.2.0.0/16 next-hop 10.0.0.1 local-preference 200",
			expect: Exa{
				Action:    "announce",
				Prefix:    "10.2.0.0/16",
				NextHop:   "10.0.0.1",
				LocalPref: uint32Ptr(200),
			},
		},
		{
			name: "announce with communities",
			line: "announce route 10.0.0.1/24 next-hop self community [ no-export 666:666 ]",
			expect: Exa{
				Action:    "announce",
				Prefix:    "10.0.0.1/24",
				NextHop:   "self",
				Community: []string{"no-export", "666:666"},
			},
		},
		{
			name: "community normalization",
			line: "announce route 10.0.0.1/24 next-hop self community [ no_export no_advertise blackhole ]",
			expect: Exa{
				Action:    "announce",
				Prefix:    "10.0.0.1/24",
				NextHop:   "self",
				Community: []string{"no-export", "no-advertise", "blackhole"},
			},
		},
		{
			name: "empty line",
			line: "",
			fail: true,
		},
		{
			name: "invalid action",
			line: "invalid route 10.0.0.1/24 next-hop self",
			fail: true,
		},
		{
			name: "not route command",
			line: "announce flowspec source 10.0.0.1/24",
			fail: true,
		},
		{
			name: "too few tokens",
			line: "announce route",
			fail: true,
		},
		{
			name: "missing next-hop value",
			line: "announce route 10.0.0.1/24 next-hop",
			fail: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			line := NewExa()
			err := line.Parse(tc.line)

			if tc.fail {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.expect.Action, line.Action)
			assert.Equal(t, tc.expect.Prefix, line.Prefix)
			assert.Equal(t, tc.expect.NextHop, line.NextHop)
			assert.Equal(t, tc.expect.Origin, line.Origin)
			assert.Equal(t, tc.expect.ASPath, line.ASPath)
			assert.Equal(t, tc.expect.MED, line.MED)
			assert.Equal(t, tc.expect.LocalPref, line.LocalPref)
			assert.Equal(t, tc.expect.Community, line.Community)
		})
	}
}

func TestLineString(t *testing.T) {
	testCases := []struct {
		name   string
		line   Exa
		expect string
	}{
		{
			name: "basic announce",
			line: Exa{
				Action:  "announce",
				Prefix:  "10.0.0.1/24",
				NextHop: "self",
			},
			expect: "announce route 10.0.0.1/24 next-hop self",
		},
		{
			name: "withdraw",
			line: Exa{
				Action: "withdraw",
				Prefix: "192.168.1.0/24",
			},
			expect: "withdraw route 192.168.1.0/24",
		},
		{
			name: "full announce",
			line: Exa{
				Action:    "announce",
				Prefix:    "172.16.0.0/12",
				NextHop:   "10.0.0.1",
				Origin:    "IGP",
				ASPath:    []uint32{65001, 65002},
				MED:       uint32Ptr(100),
				LocalPref: uint32Ptr(200),
				Community: []string{"no-export", "123:456"},
			},
			expect: "announce route 172.16.0.0/12 next-hop 10.0.0.1 origin IGP as-path [ 65001 65002 ] med 100 local-preference 200 community [ no-export 123:456 ]",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := tc.line.String()
			assert.Equal(t, tc.expect, result)
		})
	}
}

func TestIteratorMultiplePrefixes(t *testing.T) {
	// Create a bgpfix Msg with multiple reachable and unreachable prefixes
	m := msg.NewMsg()
	u := &m.Switch(msg.UPDATE).Update

	// Add multiple reachable prefixes
	prefix1, _ := netip.ParsePrefix("10.0.0.0/24")
	prefix2, _ := netip.ParsePrefix("10.0.1.0/24")
	prefix3, _ := netip.ParsePrefix("10.0.2.0/24")
	u.AddReach(nlri.FromPrefix(prefix1), nlri.FromPrefix(prefix2), nlri.FromPrefix(prefix3))

	// Add multiple unreachable prefixes
	prefix4, _ := netip.ParsePrefix("192.168.0.0/24")
	prefix5, _ := netip.ParsePrefix("192.168.1.0/24")
	u.AddUnreach(nlri.FromPrefix(prefix4), nlri.FromPrefix(prefix5))

	line := NewExa()
	var results []*Exa
	for result := range line.IterMsg(m) {
		// Make a copy since the iterator reuses the same Exa object
		copy := *result
		results = append(results, &copy)
	}

	// Should have 5 results total (3 announcements + 2 withdrawals)
	assert.Len(t, results, 5)

	// Check announcements
	announceCount := 0
	withdrawCount := 0
	for _, result := range results {
		switch result.Action {
		case "announce":
			announceCount++
			assert.Contains(t, []string{"10.0.0.0/24", "10.0.1.0/24", "10.0.2.0/24"}, result.Prefix)
		case "withdraw":
			withdrawCount++
			assert.Contains(t, []string{"192.168.0.0/24", "192.168.1.0/24"}, result.Prefix)
		}
	}

	assert.Equal(t, 3, announceCount, "Expected 3 announcements")
	assert.Equal(t, 2, withdrawCount, "Expected 2 withdrawals")
}

func TestErrorHandling(t *testing.T) {
	testCases := []struct {
		name string
		line Exa
		fail bool
	}{
		{
			name: "next-hop self should fail ToMsg",
			line: Exa{
				Action:  "announce",
				Prefix:  "10.0.0.1/24",
				NextHop: "self",
			},
			fail: true,
		},
		{
			name: "invalid prefix should fail ToMsg",
			line: Exa{
				Action:  "announce",
				Prefix:  "invalid-prefix",
				NextHop: "10.0.0.1",
			},
			fail: true,
		},
		{
			name: "invalid next-hop should fail ToMsg",
			line: Exa{
				Action:  "announce",
				Prefix:  "10.0.0.1/24",
				NextHop: "invalid-ip",
			},
			fail: true,
		},
		{
			name: "invalid origin should fail ToMsg",
			line: Exa{
				Action:  "announce",
				Prefix:  "10.0.0.1/24",
				NextHop: "10.0.0.1",
				Origin:  "INVALID",
			},
			fail: true,
		},
		{
			name: "invalid community should fail ToMsg",
			line: Exa{
				Action:    "announce",
				Prefix:    "10.0.0.1/24",
				NextHop:   "10.0.0.1",
				Community: []string{"invalid:format:too:many:colons"},
			},
			fail: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			m := msg.NewMsg()
			err := tc.line.ToMsg(m)

			if tc.fail {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// Helper function to create uint32 pointer
func uint32Ptr(v uint32) *uint32 {
	return &v
}
