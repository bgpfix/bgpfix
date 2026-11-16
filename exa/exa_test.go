package exa

import (
	"bytes"
	"cmp"
	"net/netip"
	"testing"

	"github.com/bgpfix/bgpfix/attrs"
	"github.com/bgpfix/bgpfix/caps"
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
		{
			name: "ipv6 announce /32",
			line: "announce route 2001:db8::/32 next-hop 2001:db8::1",
		},
		{
			name: "ipv6 announce /48",
			line: "announce route 2001:db8:1::/48 next-hop 2001:db8::1",
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

				// Compare the essential fields
				assert.Equal(t, src.Action, dst.Action, "Action mismatch")
				assert.Equal(t, src.Prefixes, dst.Prefixes, "Prefix mismatch")

				// For withdrawals, attributes are not preserved, so only check for announcements
				if src.Action == "announce" {
					assert.Equal(t, src.NextHop, dst.NextHop, "NextHop mismatch")
					assert.Equal(t, cmp.Or(src.Origin, "IGP"), dst.Origin, "Origin mismatch") // NB: the default
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
				Action:   "announce",
				Prefixes: []string{"10.0.0.1/24"},
				NextHop:  "self",
			},
		},
		{
			name: "basic withdraw",
			line: "withdraw route 192.168.1.0/24",
			expect: Exa{
				Action:   "withdraw",
				Prefixes: []string{"192.168.1.0/24"},
			},
		},
		{
			name: "withdraw with attributes",
			line: "withdraw route 192.168.1.0/24 next-hop 10.0.0.1 as-path [ 65001 ]",
			expect: Exa{
				Action:   "withdraw",
				Prefixes: []string{"192.168.1.0/24"},
			},
		},
		{
			name: "compact lists, single values, ipv4 unicast",
			line: "announce ipv4 unicast 10.0.0.0/8 next-hop 10.0.0.1 as-path [65001 65002] community 65000:1 large-community [65000:1:2]",
			expect: Exa{
				Action:         "announce",
				Prefixes:       []string{"10.0.0.0/8"},
				NextHop:        "10.0.0.1",
				ASPath:         []uint32{65001, 65002},
				Community:      []string{"65000:1"},
				LargeCommunity: []string{"65000:1:2"},
			},
		},
		{
			name: "neighbor selector, more attributes",
			line: "neighbor 192.0.2.1 local-as 65000 announce route 10.0.0.0/8 next-hop 10.0.0.1 extended-community [target:65000:1 0x0002fde800000001] atomic-aggregate aggregator (65000:192.0.2.9) originator-id 192.0.2.7 cluster-list [192.0.2.8]",
			expect: Exa{
				Action:   "announce",
				Prefixes: []string{"10.0.0.0/8"},
				NextHop:  "10.0.0.1",
			},
		},
		{
			name: "unsupported attribute",
			line: "announce route 10.0.0.0/8 next-hop 10.0.0.1 label 100",
			fail: true,
		},
		{
			name: "invalid med",
			line: "announce route 10.0.0.0/8 next-hop 10.0.0.1 med abc",
			fail: true,
		},
		{
			name: "announce with origin",
			line: "announce route 10.0.0.0/8 next-hop 192.168.1.1 origin IGP",
			expect: Exa{
				Action:   "announce",
				Prefixes: []string{"10.0.0.0/8"},
				NextHop:  "192.168.1.1",
				Origin:   "IGP",
			},
		},
		{
			name: "announce with as-path",
			line: "announce route 172.16.0.0/12 next-hop 10.0.0.1 as-path [ 65001 65002 ]",
			expect: Exa{
				Action:   "announce",
				Prefixes: []string{"172.16.0.0/12"},
				NextHop:  "10.0.0.1",
				ASPath:   []uint32{65001, 65002},
			},
		},
		{
			name: "announce with med",
			line: "announce route 10.1.0.0/16 next-hop 10.0.0.1 med 100",
			expect: Exa{
				Action:   "announce",
				Prefixes: []string{"10.1.0.0/16"},
				NextHop:  "10.0.0.1",
				MED:      uint32Ptr(100),
			},
		},
		{
			name: "announce with local-preference",
			line: "announce route 10.2.0.0/16 next-hop 10.0.0.1 local-preference 200",
			expect: Exa{
				Action:    "announce",
				Prefixes:  []string{"10.2.0.0/16"},
				NextHop:   "10.0.0.1",
				LocalPref: uint32Ptr(200),
			},
		},
		{
			name: "announce with communities",
			line: "announce route 10.0.0.1/24 next-hop self community [ no-export 666:666 ]",
			expect: Exa{
				Action:    "announce",
				Prefixes:  []string{"10.0.0.1/24"},
				NextHop:   "self",
				Community: []string{"no-export", "666:666"},
			},
		},
		{
			name: "community normalization",
			line: "announce route 10.0.0.1/24 next-hop self community [ no_export no_advertise blackhole ]",
			expect: Exa{
				Action:    "announce",
				Prefixes:  []string{"10.0.0.1/24"},
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
		{
			name: "ipv6 basic announce",
			line: "announce route 2001:db8::/32 next-hop 2001:db8::1",
			expect: Exa{
				Action:   "announce",
				Prefixes: []string{"2001:db8::/32"},
				NextHop:  "2001:db8::1",
			},
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
			assert.Equal(t, tc.expect.Prefixes, line.Prefixes)
			assert.Equal(t, tc.expect.NextHop, line.NextHop)
			assert.Equal(t, tc.expect.Origin, line.Origin)
			assert.Equal(t, tc.expect.ASPath, line.ASPath)
			assert.Equal(t, tc.expect.MED, line.MED)
			assert.Equal(t, tc.expect.LocalPref, line.LocalPref)
			assert.Equal(t, tc.expect.Community, line.Community)
			assert.Equal(t, tc.expect.LargeCommunity, line.LargeCommunity)
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
				Action:   "announce",
				Prefixes: []string{"10.0.0.1/24"},
				NextHop:  "self",
			},
			expect: "announce route 10.0.0.1/24 next-hop self",
		},
		{
			name: "withdraw",
			line: Exa{
				Action:   "withdraw",
				Prefixes: []string{"192.168.1.0/24"},
			},
			expect: "withdraw route 192.168.1.0/24",
		},
		{
			name: "full announce",
			line: Exa{
				Action:    "announce",
				Prefixes:  []string{"172.16.0.0/12"},
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
	u.Attrs.Use(attrs.ATTR_ORIGIN)

	// Add multiple unreachable prefixes
	prefix4, _ := netip.ParsePrefix("192.168.0.0/24")
	prefix5, _ := netip.ParsePrefix("192.168.1.0/24")
	u.AddUnreach(nlri.FromPrefix(prefix4), nlri.FromPrefix(prefix5))

	// one line for all announcements, one for all withdrawals
	var lines []string
	x := NewExa()
	for range x.IterMsg(m) {
		lines = append(lines, x.String())
	}
	assert.Equal(t, []string{
		"announce attributes origin IGP nlri 10.0.0.0/24 10.0.1.0/24 10.0.2.0/24",
		"withdraw attributes nlri 192.168.0.0/24 192.168.1.0/24",
	}, lines)

	// and back
	for i, line := range lines {
		y, err := NewExaLine(line)
		require.NoError(t, err)
		m2 := msg.NewMsg()
		require.NoError(t, y.ToMsg(m2))
		assert.Equal(t, 3-i, len(y.Prefixes))
		assert.Equal(t, i == 0, m2.Update.HasReach())
		assert.Equal(t, i == 1, m2.Update.HasUnreach())
	}

	// mixed address families do not fit one UPDATE
	y, err := NewExaLine("announce attributes next-hop 10.0.0.1 nlri 10.0.0.0/24 2001:db8::/32")
	require.NoError(t, err)
	assert.Error(t, y.ToMsg(msg.NewMsg()))
}

func TestErrorHandling(t *testing.T) {
	testCases := []struct {
		name string
		line Exa
		fail bool
	}{
		{
			name: "invalid prefix should fail ToMsg",
			line: Exa{
				Action:   "announce",
				Prefixes: []string{"invalid-prefix"},
				NextHop:  "10.0.0.1",
			},
			fail: true,
		},
		{
			name: "invalid next-hop should fail ToMsg",
			line: Exa{
				Action:   "announce",
				Prefixes: []string{"10.0.0.1/24"},
				NextHop:  "invalid-ip",
			},
			fail: true,
		},
		{
			name: "invalid origin should fail ToMsg",
			line: Exa{
				Action:   "announce",
				Prefixes: []string{"10.0.0.1/24"},
				NextHop:  "10.0.0.1",
				Origin:   "INVALID",
			},
			fail: true,
		},
		{
			name: "invalid community should fail ToMsg",
			line: Exa{
				Action:    "announce",
				Prefixes:  []string{"10.0.0.1/24"},
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

func TestMoreAttributes(t *testing.T) {
	// what ExaBGP accepts -> what we write back
	lines := map[string]string{
		"neighbor 192.0.2.1 announce route 10.0.0.0/8 next-hop 10.0.0.1 extended-community [target:65000:1 origin:192.0.2.1:2 target:4200000000:3 0x4002fde800000001] atomic-aggregate aggregator (65000:192.0.2.9)": "announce route 10.0.0.0/8 next-hop 10.0.0.1 origin IGP extended-community [ target:65000:1 origin:192.0.2.1:2 target:4200000000:3 0x4002fde800000001 ] atomic-aggregate aggregator ( 65000:192.0.2.9 )",
		"announce route 10.0.0.0/8 next-hop 10.0.0.1 originator-id 192.0.2.7 cluster-list [192.0.2.8 192.0.2.9]":                                                                                                     "announce route 10.0.0.0/8 next-hop 10.0.0.1 origin IGP originator-id 192.0.2.7 cluster-list [ 192.0.2.8 192.0.2.9 ]",
	}
	for line, want := range lines {
		x, err := NewExaLine(line)
		require.NoError(t, err, line)
		m := msg.NewMsg()
		require.NoError(t, x.ToMsg(m), line)

		// NB: over the wire
		require.NoError(t, m.Marshal(caps.Caps{}))
		var wire bytes.Buffer
		m.WriteTo(&wire)
		m2 := msg.NewMsg()
		_, err = m2.FromBytes(wire.Bytes())
		require.NoError(t, err)
		require.NoError(t, m2.Parse(caps.Caps{}))

		y := NewExa()
		for range y.IterMsg(m2) {
			assert.Equal(t, want, y.String())
		}
	}

	for _, bad := range []string{"extended-community target:1", "extended-community foo:1:2", "extended-community target:65000:4294967296", "aggregator 65000", "cluster-list [ x ]"} {
		x, err := NewExaLine("announce route 10.0.0.0/8 next-hop 10.0.0.1 " + bad)
		require.NoError(t, err, bad)
		assert.Error(t, x.ToMsg(msg.NewMsg()), bad)
	}
}

// NB: the expected lines were checked against ExaBGP 5.0.15, which sends the same for both forms
func TestFlow(t *testing.T) {
	lines := [][2]string{
		{"announce flow route { match { destination 10.0.0.1/32; protocol tcp; destination-port =80; } then { discard; } }",
			"announce flow route destination 10.0.0.1/32 protocol =6 destination-port =80 discard"},
		{"announce flow route destination 10.0.0.2/32 source 192.0.2.0/24 protocol [ =tcp =udp ] port >1024&<2048 rate-limit 9600",
			"announce flow route destination 10.0.0.2/32 source 192.0.2.0/24 protocol [ =6 =17 ] port >1024&<2048 rate-limit 9600"},
		{"announce flow route { match { destination 10.0.0.3/32; tcp-flags [ syn !ack ]; packet-length >=100&<=200; fragment [ is-fragment first-fragment ]; } then { redirect 65000:100; action sample-terminal; } }",
			"announce flow route destination 10.0.0.3/32 tcp-flags [ 0x2 !0x10 ] packet-length >=100&<=200 fragment [ 0x2 0x4 ] redirect 65000:100 action sample-terminal"},
		{"announce flow route { match { destination 10.0.0.4/32; icmp-type =8; icmp-code =0; dscp =10; source-port =53; } then { mark 12; community [65000:1]; } }",
			"announce flow route destination 10.0.0.4/32 source-port =53 icmp-type =8 icmp-code =0 dscp =10 mark 12 community [ 65000:1 ]"},
		{"announce flow route { match { destination 2001:db8::/48; next-header udp; destination-port =53; } then { rate-limit 1000 packets; } }",
			"announce flow route destination 2001:db8::/48 next-header =17 destination-port =53 rate-limit 1000 packets"},
		{"announce flow route { match { destination 10.0.0.5/32; tcp-flags [ =syn+ack fin&!rst ]; } then { redirect 192.0.2.9; } }",
			"announce flow route destination 10.0.0.5/32 tcp-flags [ =0x12 0x1&!0x4 ] redirect 192.0.2.9"},
		{"announce flow route { match { destination 10.0.0.6/32; protocol 6; tcp-flags 0x12; } then { copy 192.0.2.9; extended-community [ target:65000:1 ]; } }",
			"announce flow route destination 10.0.0.6/32 protocol =6 tcp-flags 0x12 copy 192.0.2.9 extended-community [ target:65000:1 ]"},
		{"announce flow route { match { destination 10.0.0.7/32; } then { redirect 4200000000:5; redirect-to-nexthop; } }",
			"announce flow route destination 10.0.0.7/32 redirect 4200000000:5 redirect-to-nexthop"},
		{"announce flow route { match { source 2001:db8:1::/64/32; flow-label =5; traffic-class =3; } then { discard; } }",
			"announce flow route source 0:0:1::/64/32 traffic-class =3 flow-label =5 discard"}, // NB: only the bits after the offset are sent
		{"announce flow route destination 2001:db8::/48 redirect 2001:db8::1",
			"announce flow route destination 2001:db8::/48 redirect 2001:db8::1"},
		{"announce flow route destination 10.0.0.8/32 extended-community [ 0x8007000000000000 0x8006000a3f000000 ]", // NB: no names for these
			"announce flow route destination 10.0.0.8/32 extended-community [ 0x8007000000000000 0x8006000a3f000000 ]"},
		{"withdraw flow route { match { destination 10.0.0.1/32; protocol tcp; destination-port =80; } then { discard; } }",
			"withdraw flow route destination 10.0.0.1/32 protocol =6 destination-port =80"},
	}
	for _, l := range lines {
		x, err := NewExaLine(l[0])
		require.NoError(t, err, l[0])
		m := msg.NewMsg()
		require.NoError(t, x.ToMsg(m), l[0])

		// NB: over the wire
		require.NoError(t, m.Marshal(caps.Caps{}))
		var wire bytes.Buffer
		m.WriteTo(&wire)
		m2 := msg.NewMsg()
		_, err = m2.FromBytes(wire.Bytes())
		require.NoError(t, err)
		require.NoError(t, m2.Parse(caps.Caps{}))

		n := 0
		y := NewExa()
		for range y.IterMsg(m2) {
			assert.Equal(t, l[1], y.String())
			n++
		}
		assert.Equal(t, 1, n, l[0])
	}

	for _, bad := range []string{"then { discard; }", "destination 10.0.0.1/32 destination-port =http", "destination 10.0.0.1/32 tcp-flags =", "destination 10.0.0.1/33", "destination 10.0.0.1/32 rate-limit x", "source 2001:db8::/32/40",
		"destination 10.0.0.0/8 next-header udp discard", "destination-ipv4 2001:db8::/32 discard", "destination 10.0.0.1/32 redirect 4200000000:65536"} {
		x, err := NewExaLine("announce flow route " + bad)
		if err == nil {
			err = x.ToMsg(msg.NewMsg())
		}
		assert.Error(t, err, bad)
	}
}

// an UPDATE with IPv4 and IPv6 routes takes a line per address family, each with its next-hop
func TestMixedFamilies(t *testing.T) {
	m := msg.NewMsg()
	x, err := NewExaLine("announce attributes next-hop 192.0.2.1 med 5 nlri 10.0.0.0/24 10.0.1.0/24")
	require.NoError(t, err)
	require.NoError(t, x.ToMsg(m))
	m.Update.AddReach(nlri.FromPrefix(netip.MustParsePrefix("2001:db8::/32")))
	m.Update.ReachMP().Prefixes().NextHop = netip.MustParseAddr("2001:db8::1")

	var lines []string
	x = NewExa()
	for range x.IterMsg(m) {
		lines = append(lines, x.String())
		_, err := NewExaLine(x.String())
		require.NoError(t, err)
		require.NoError(t, x.ToMsg(msg.NewMsg()))
	}
	assert.Equal(t, []string{
		"announce attributes next-hop 192.0.2.1 origin IGP med 5 nlri 10.0.0.0/24 10.0.1.0/24",
		"announce route 2001:db8::/32 next-hop 2001:db8::1 origin IGP med 5",
	}, lines)
}
