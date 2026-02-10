package filter

import (
	"net/netip"
	"testing"

	"github.com/bgpfix/bgpfix/attrs"
	"github.com/bgpfix/bgpfix/msg"
	"github.com/bgpfix/bgpfix/nlri"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- helpers ---

// newUpdate creates a minimal UPDATE message
func newUpdate() *msg.Msg {
	m := msg.NewMsg()
	m.Switch(msg.UPDATE)
	return m
}

// addReach adds reachable prefixes to msg
func addReach(m *msg.Msg, prefixes ...string) {
	for _, s := range prefixes {
		p, _ := netip.ParsePrefix(s)
		m.Update.AddReach(nlri.FromPrefix(p))
	}
}

// addUnreach adds unreachable prefixes to msg
func addUnreach(m *msg.Msg, prefixes ...string) {
	for _, s := range prefixes {
		p, _ := netip.ParsePrefix(s)
		m.Update.AddUnreach(nlri.FromPrefix(p))
	}
}

// setOrigin sets the ORIGIN attribute
func setOrigin(m *msg.Msg, origin byte) {
	a := m.Update.Attrs.Use(attrs.ATTR_ORIGIN).(*attrs.Origin)
	a.Origin = origin
}

// setAsPath sets the AS_PATH attribute from a list of ASNs (single AS_SEQUENCE)
func setAsPath(m *msg.Msg, asns ...uint32) {
	a := m.Update.Attrs.Use(attrs.ATTR_ASPATH).(*attrs.Aspath)
	a.Segments = append(a.Segments[:0], attrs.AspathSegment{List: asns})
}

// setNextHop sets the NEXT_HOP attribute
func setNextHop(m *msg.Msg, ip string) {
	a := m.Update.Attrs.Use(attrs.ATTR_NEXTHOP).(*attrs.IP)
	a.Addr, _ = netip.ParseAddr(ip)
}

// setMed sets the MED attribute
func setMed(m *msg.Msg, med uint32) {
	a := m.Update.Attrs.Use(attrs.ATTR_MED).(*attrs.U32)
	a.Val = med
}

// setLocalPref sets the LOCAL_PREF attribute
func setLocalPref(m *msg.Msg, lp uint32) {
	a := m.Update.Attrs.Use(attrs.ATTR_LOCALPREF).(*attrs.U32)
	a.Val = lp
}

// setCommunity sets standard communities from "ASN:VALUE" pairs
func setCommunity(m *msg.Msg, pairs ...string) {
	c := m.Update.Attrs.Use(attrs.ATTR_COMMUNITY).(*attrs.Community)
	err := c.FromJSON([]byte(`[` + joinQuoted(pairs) + `]`))
	if err != nil {
		panic(err)
	}
}

func joinQuoted(ss []string) string {
	out := ""
	for i, s := range ss {
		if i > 0 {
			out += ","
		}
		out += `"` + s + `"`
	}
	return out
}

// evalFilter creates a filter, evaluates against msg, returns result
func evalFilter(t *testing.T, m *msg.Msg, filter string) bool {
	t.Helper()
	f, err := NewFilter(filter)
	require.NoError(t, err, "parse: %s", filter)
	ev := NewEval(false)
	ev.SetMsg(m)
	return ev.Run(f)
}

// --- parse tests ---

func TestParseValid(t *testing.T) {
	valid := []string{
		// type shortcuts
		"update",
		"open",
		"keepalive",
		"!update",

		// af
		"ipv4",
		"ipv6",
		`af == ipv4/flowspec`,

		// prefix
		"prefix == 192.168.0.0/24",
		"reach ~ 10.0.0.0/8",
		"unreach == 2001:db8::/32",
		"prefix[*] ~ 0.0.0.0/0",

		// aspath
		"aspath",
		"as_origin == 65001",
		"as_path[-1] == 65001",
		"aspath[0] < 1000",
		"aspath ~ \"65001\"",
		"as_peer >= 100",
		"as_upstream == 3356",

		// aspath_len
		"aspath_len > 5",
		"aspath_len == 0",
		"as_path_len <= 10",
		"aspath_len",

		// nexthop
		"nexthop",
		"nh == 192.0.2.1",
		"nexthop ~ 10.0.0.0/8",

		// origin
		"origin",
		"origin == igp",
		"origin == egp",
		"origin == incomplete",
		"origin == 0",
		"origin != igp",

		// med
		"med",
		"med == 100",
		"med > 0",
		"metric <= 500",

		// local_pref
		"local_pref",
		"localpref == 100",
		"local_pref > 50",
		"local_pref <= 200",

		// community
		`community`,
		`community == "3356:100"`,
		`com ~ "3356:"`,

		// tags
		`tag[source] == ris-live`,
		`tags`,

		// complex
		`!(UPDATE && (as_origin == 39282 || !aspath[0] < 1000))`,
		"ipv4 && as_origin == 15169",
		"prefix ~ 8.0.0.0/8 || prefix ~ 2001:db8::/32",

		// no space after index (tests parser bug fix)
		"aspath[0]== 65001",
	}

	for _, tc := range valid {
		t.Run(tc, func(t *testing.T) {
			_, err := NewFilter(tc)
			assert.NoError(t, err)
		})
	}
}

func TestParseInvalid(t *testing.T) {
	invalid := []struct {
		filter string
		name   string
	}{
		{"", "empty"},
		{"foobar == 1", "unknown attr"},
		{"origin == bogus", "bad origin value"},
		{"origin == 5", "origin out of range"},
		{"med == hello", "med non-integer"},
		{"med ~ 100", "med like"},
		{"local_pref ~ 100", "localpref like"},
		{"aspath_len ~ 5", "aspath_len like"},
		{"aspath_len == -1", "aspath_len negative"},
		{"prefix ==", "missing value"},
		{"prefix == not_a_prefix", "bad prefix value"},
		{"(prefix == 1.2.3.4/32", "unmatched open paren"},
		{"prefix == 1.2.3.4/32)", "unmatched close paren"},
		{"af < 1", "af bad op"},
		{"type ~ UPDATE", "type bad op"},
		{"prefix[bad] == 1.2.3.4/32", "prefix bad index"},
	}

	for _, tc := range invalid {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewFilter(tc.filter)
			assert.Error(t, err, "expected error for: %s", tc.filter)
		})
	}
}

// --- eval tests ---

func TestEvalType(t *testing.T) {
	upd := newUpdate()
	assert.True(t, evalFilter(t, upd, "update"))
	assert.False(t, evalFilter(t, upd, "open"))
	assert.False(t, evalFilter(t, upd, "keepalive"))
	assert.True(t, evalFilter(t, upd, "!open"))
	assert.True(t, evalFilter(t, upd, `type == UPDATE`))
	assert.False(t, evalFilter(t, upd, `type == OPEN`))

	ka := msg.NewMsg()
	ka.Switch(msg.KEEPALIVE)
	assert.True(t, evalFilter(t, ka, "keepalive"))
	assert.False(t, evalFilter(t, ka, "update"))
}

func TestEvalPrefix(t *testing.T) {
	m := newUpdate()
	addReach(m, "10.1.0.0/16", "192.168.1.0/24")
	addUnreach(m, "172.16.0.0/12")

	// reach
	assert.True(t, evalFilter(t, m, "reach"))
	assert.True(t, evalFilter(t, m, "reach == 10.1.0.0/16"))
	assert.False(t, evalFilter(t, m, "reach == 10.1.0.0/24"))
	assert.True(t, evalFilter(t, m, "reach ~ 10.0.0.0/8"))
	assert.False(t, evalFilter(t, m, "reach ~ 172.16.0.0/12"))

	// unreach
	assert.True(t, evalFilter(t, m, "unreach"))
	assert.True(t, evalFilter(t, m, "unreach ~ 172.16.0.0/12"))
	assert.False(t, evalFilter(t, m, "unreach ~ 10.0.0.0/8"))

	// prefix (either)
	assert.True(t, evalFilter(t, m, "prefix == 172.16.0.0/12"))
	assert.True(t, evalFilter(t, m, "prefix == 10.1.0.0/16"))

	// less/more specific
	assert.True(t, evalFilter(t, m, "prefix < 10.0.0.0/8"))   // 10.1.0.0/16 is more specific than /8
	assert.False(t, evalFilter(t, m, "prefix < 10.1.0.0/16"))  // not strictly more specific than self
	assert.True(t, evalFilter(t, m, "prefix <= 10.1.0.0/16"))  // equal counts
	assert.True(t, evalFilter(t, m, "prefix > 10.1.0.0/24"))   // 10.1.0.0/16 is less specific than /24
	assert.False(t, evalFilter(t, m, "prefix > 10.1.0.0/16"))  // not strictly less specific than self
	assert.True(t, evalFilter(t, m, "prefix >= 10.1.0.0/16"))  // equal counts

	// prefix[*] - all must match
	assert.True(t, evalFilter(t, m, "prefix[*] ~ 0.0.0.0/0"))   // all overlap 0/0
	assert.False(t, evalFilter(t, m, "prefix[*] ~ 10.0.0.0/8")) // 192.168 and 172.16 don't match

	// negation
	assert.False(t, evalFilter(t, m, "!reach"))
	assert.True(t, evalFilter(t, m, "prefix !~ 8.8.0.0/16"))
}

func TestEvalAsPath(t *testing.T) {
	m := newUpdate()
	addReach(m, "10.0.0.0/24")
	setAsPath(m, 65001, 3356, 15169)

	// existence
	assert.True(t, evalFilter(t, m, "aspath"))

	// any hop match
	assert.True(t, evalFilter(t, m, "aspath == 3356"))
	assert.False(t, evalFilter(t, m, "aspath == 9999"))

	// indexed
	assert.True(t, evalFilter(t, m, "aspath[0] == 65001"))  // first hop
	assert.True(t, evalFilter(t, m, "aspath[-1] == 15169")) // last hop (origin)
	assert.True(t, evalFilter(t, m, "aspath[1] == 3356"))
	assert.False(t, evalFilter(t, m, "aspath[0] == 3356"))

	// shortcuts
	assert.True(t, evalFilter(t, m, "as_origin == 15169"))
	assert.True(t, evalFilter(t, m, "as_peer == 65001"))
	assert.True(t, evalFilter(t, m, "as_upstream == 3356"))

	// comparisons
	assert.True(t, evalFilter(t, m, "as_origin > 10000"))
	assert.True(t, evalFilter(t, m, "as_origin < 20000"))
	assert.True(t, evalFilter(t, m, "as_origin >= 15169"))
	assert.True(t, evalFilter(t, m, "as_origin <= 15169"))
	assert.False(t, evalFilter(t, m, "as_origin > 15169"))

	// regex
	assert.True(t, evalFilter(t, m, `aspath ~ "15169"`))
	assert.True(t, evalFilter(t, m, `aspath ~ "3356,15169$"`))
	assert.False(t, evalFilter(t, m, `aspath ~ "^15169"`))

	// negation
	assert.True(t, evalFilter(t, m, "as_origin != 9999"))
	assert.False(t, evalFilter(t, m, "as_origin != 15169"))

	// empty aspath
	m2 := newUpdate()
	addReach(m2, "10.0.0.0/24")
	assert.False(t, evalFilter(t, m2, "aspath"))
}

func TestEvalAspathLen(t *testing.T) {
	m := newUpdate()
	addReach(m, "10.0.0.0/24")
	setAsPath(m, 65001, 3356, 15169)

	assert.True(t, evalFilter(t, m, "aspath_len"))
	assert.True(t, evalFilter(t, m, "aspath_len == 3"))
	assert.False(t, evalFilter(t, m, "aspath_len == 2"))
	assert.True(t, evalFilter(t, m, "aspath_len > 2"))
	assert.True(t, evalFilter(t, m, "aspath_len >= 3"))
	assert.True(t, evalFilter(t, m, "aspath_len < 5"))
	assert.True(t, evalFilter(t, m, "aspath_len <= 3"))
	assert.False(t, evalFilter(t, m, "aspath_len > 3"))

	// no aspath
	m2 := newUpdate()
	addReach(m2, "10.0.0.0/24")
	assert.False(t, evalFilter(t, m2, "aspath_len"))
	assert.False(t, evalFilter(t, m2, "aspath_len == 0"))
}

func TestEvalOrigin(t *testing.T) {
	m := newUpdate()
	addReach(m, "10.0.0.0/24")
	setOrigin(m, 0) // IGP

	assert.True(t, evalFilter(t, m, "origin"))
	assert.True(t, evalFilter(t, m, "origin == igp"))
	assert.True(t, evalFilter(t, m, "origin == 0"))
	assert.False(t, evalFilter(t, m, "origin == egp"))
	assert.False(t, evalFilter(t, m, "origin == incomplete"))
	assert.True(t, evalFilter(t, m, "origin != egp"))
	assert.False(t, evalFilter(t, m, "origin != igp"))

	// no origin
	m2 := newUpdate()
	addReach(m2, "10.0.0.0/24")
	assert.False(t, evalFilter(t, m2, "origin"))
	assert.False(t, evalFilter(t, m2, "origin == igp"))
}

func TestEvalMed(t *testing.T) {
	m := newUpdate()
	addReach(m, "10.0.0.0/24")
	setMed(m, 500)

	assert.True(t, evalFilter(t, m, "med"))
	assert.True(t, evalFilter(t, m, "med == 500"))
	assert.False(t, evalFilter(t, m, "med == 100"))
	assert.True(t, evalFilter(t, m, "med > 100"))
	assert.True(t, evalFilter(t, m, "med >= 500"))
	assert.True(t, evalFilter(t, m, "med < 1000"))
	assert.True(t, evalFilter(t, m, "med <= 500"))
	assert.False(t, evalFilter(t, m, "med > 500"))

	// no med
	m2 := newUpdate()
	addReach(m2, "10.0.0.0/24")
	assert.False(t, evalFilter(t, m2, "med"))
}

func TestEvalLocalPref(t *testing.T) {
	m := newUpdate()
	addReach(m, "10.0.0.0/24")
	setLocalPref(m, 150)

	assert.True(t, evalFilter(t, m, "local_pref"))
	assert.True(t, evalFilter(t, m, "localpref == 150"))
	assert.True(t, evalFilter(t, m, "local_pref > 100"))
	assert.True(t, evalFilter(t, m, "local_pref < 200"))
	assert.True(t, evalFilter(t, m, "local_pref >= 150"))
	assert.True(t, evalFilter(t, m, "local_pref <= 150"))
	assert.False(t, evalFilter(t, m, "local_pref > 150"))

	// no local_pref
	m2 := newUpdate()
	addReach(m2, "10.0.0.0/24")
	assert.False(t, evalFilter(t, m2, "local_pref"))
}

func TestEvalNexthop(t *testing.T) {
	m := newUpdate()
	addReach(m, "10.0.0.0/24")
	setNextHop(m, "192.0.2.1")

	assert.True(t, evalFilter(t, m, "nexthop"))
	assert.True(t, evalFilter(t, m, "nh == 192.0.2.1"))
	assert.False(t, evalFilter(t, m, "nh == 192.0.2.2"))
	assert.True(t, evalFilter(t, m, "nexthop ~ 192.0.2.0/24"))
	assert.False(t, evalFilter(t, m, "nexthop ~ 10.0.0.0/8"))

	// no nexthop
	m2 := newUpdate()
	addReach(m2, "10.0.0.0/24")
	assert.False(t, evalFilter(t, m2, "nexthop"))
}

func TestEvalCommunity(t *testing.T) {
	m := newUpdate()
	addReach(m, "10.0.0.0/24")
	setCommunity(m, "3356:100", "174:200")

	assert.True(t, evalFilter(t, m, "community"))
	assert.True(t, evalFilter(t, m, `community == "3356:100"`))
	assert.False(t, evalFilter(t, m, `community == "3356:999"`))
	assert.True(t, evalFilter(t, m, `com ~ "3356:"`))
	assert.True(t, evalFilter(t, m, `com ~ "174"`))
	assert.False(t, evalFilter(t, m, `com ~ "^9999:"`))

	// negation
	assert.True(t, evalFilter(t, m, `community != "9999:100"`))
	assert.False(t, evalFilter(t, m, `community != "3356:100"`))

	// no community
	m2 := newUpdate()
	addReach(m2, "10.0.0.0/24")
	assert.False(t, evalFilter(t, m2, "community"))
}

func TestEvalTag(t *testing.T) {
	m := newUpdate()
	ev := NewEval(false)
	ev.SetMsg(m)
	ev.PipeTags = map[string]string{
		"source": "ris-live",
		"region": "eu-west",
	}

	f1, _ := NewFilter(`tag[source] == ris-live`)
	assert.True(t, ev.Run(f1))

	f2, _ := NewFilter(`tag[source] == rv-live`)
	assert.False(t, ev.Run(f2))

	f3, _ := NewFilter(`tag[region] ~ "^eu-"`)
	assert.True(t, ev.Run(f3))

	f4, _ := NewFilter(`tags`)
	assert.True(t, ev.Run(f4))

	// tags work on non-UPDATE types
	ka := msg.NewMsg()
	ka.Switch(msg.KEEPALIVE)
	ev.SetMsg(ka)
	ev.PipeTags = map[string]string{"source": "test"}
	f5, _ := NewFilter(`tag[source] == test`)
	assert.True(t, ev.Run(f5))

	// no tags
	ev.PipeTags = nil
	assert.False(t, ev.Run(f4))
}

func TestEvalNonUpdate(t *testing.T) {
	// non-UPDATE messages should fail UPDATE-only filters
	ka := msg.NewMsg()
	ka.Switch(msg.KEEPALIVE)

	assert.False(t, evalFilter(t, ka, "prefix == 10.0.0.0/24"))
	assert.False(t, evalFilter(t, ka, "aspath"))
	assert.False(t, evalFilter(t, ka, "origin == igp"))
	assert.False(t, evalFilter(t, ka, "med > 0"))

	// but type filters work
	assert.True(t, evalFilter(t, ka, "keepalive"))
	assert.False(t, evalFilter(t, ka, "update"))
}

// --- logic tests ---

func TestEvalAndOr(t *testing.T) {
	m := newUpdate()
	addReach(m, "10.0.0.0/24")
	setOrigin(m, 0) // IGP
	setAsPath(m, 65001, 15169)

	// basic AND
	assert.True(t, evalFilter(t, m, "origin == igp && as_origin == 15169"))
	assert.False(t, evalFilter(t, m, "origin == igp && as_origin == 9999"))

	// basic OR
	assert.True(t, evalFilter(t, m, "origin == egp || as_origin == 15169"))
	assert.True(t, evalFilter(t, m, "origin == igp || as_origin == 9999"))
	assert.False(t, evalFilter(t, m, "origin == egp || as_origin == 9999"))

	// left-to-right evaluation (no operator precedence, use parens for grouping)
	// A && B || C: A=false => false (AND short-circuit)
	assert.False(t, evalFilter(t, m, "origin == egp && as_origin == 15169 || update"))
	// A && B || C: A=true, B=false => false (AND short-circuit)
	assert.False(t, evalFilter(t, m, "origin == igp && as_origin == 9999 || update"))
	// A || B && C: A=true => true (OR short-circuit)
	assert.True(t, evalFilter(t, m, "update || origin == egp && as_origin == 9999"))
	// A || B && C: A=false, B=true, C=true => true
	assert.True(t, evalFilter(t, m, "open || origin == igp && as_origin == 15169"))
	// A || B && C: A=false, B=true, C=false => false
	assert.False(t, evalFilter(t, m, "open || origin == igp && as_origin == 9999"))

	// triple AND
	assert.True(t, evalFilter(t, m, "update && origin == igp && as_origin == 15169"))
	assert.False(t, evalFilter(t, m, "update && origin == egp && as_origin == 15169"))

	// triple OR
	assert.True(t, evalFilter(t, m, "open || origin == egp || as_origin == 15169"))
	assert.False(t, evalFilter(t, m, "open || origin == egp || as_origin == 9999"))
}

func TestEvalParens(t *testing.T) {
	m := newUpdate()
	addReach(m, "10.0.0.0/24")
	setOrigin(m, 0)
	setAsPath(m, 65001, 15169)

	// parenthesized sub-expression
	assert.True(t, evalFilter(t, m, "(origin == igp)"))
	assert.True(t, evalFilter(t, m, "(origin == igp && as_origin == 15169)"))
	assert.False(t, evalFilter(t, m, "!(origin == igp)"))

	// nested
	assert.True(t, evalFilter(t, m, "update && (origin == igp || origin == egp)"))
	assert.False(t, evalFilter(t, m, "!update && (origin == igp || origin == egp)"))

	// complex from original test:
	// aspath[0]=65001 >= 1000, so !aspath[0]<1000 = true
	// as_origin=15169 != 39282, but OR with true = true
	// UPDATE && true = true, negated = false
	assert.False(t, evalFilter(t, m, `!(UPDATE && (as_origin == 39282 || !aspath[0] < 1000))`))
}

func TestEvalCache(t *testing.T) {
	m := newUpdate()
	addReach(m, "10.0.0.0/24")
	setOrigin(m, 0)

	f, err := NewFilter("origin == igp && reach")
	require.NoError(t, err)

	ev := NewEval(true) // with cache
	ev.SetMsg(m)

	// first eval populates cache
	assert.True(t, ev.Run(f))

	// second eval uses cache
	assert.True(t, ev.Run(f))

	// change message version -> cache invalidated
	m.Edit()
	setOrigin(m, 1) // EGP
	assert.False(t, ev.Run(f))
}
