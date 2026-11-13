package msg

import (
	"net/netip"
	"testing"

	"github.com/bgpfix/bgpfix/afi"
	"github.com/bgpfix/bgpfix/attrs"
	"github.com/bgpfix/bgpfix/nlri"
	"github.com/stretchr/testify/assert"
)

func TestUpdate_AddUnreachMixedFamilies(t *testing.T) {
	p4 := nlri.FromPrefix(netip.MustParsePrefix("192.0.2.0/24"))
	p6 := nlri.FromPrefix(netip.MustParsePrefix("2001:db8::/48"))
	q6 := nlri.FromPrefix(netip.MustParsePrefix("2001:db8:1::/48"))

	// existing IPv6 MP_UNREACH, add IPv4 and IPv6
	m := NewMsg()
	m.Switch(UPDATE)
	m.Update.AddUnreach(p6)
	m.Update.AddUnreach(p4, q6)
	assert.ElementsMatch(t, []nlri.Prefix{p4, p6, q6}, m.Update.AllUnreach())

	// existing IPv4 MP_UNREACH, add IPv6: IPv4 withdrawals survive
	m = NewMsg()
	m.Switch(UPDATE)
	mp := m.Update.Attrs.Use(attrs.ATTR_MP_UNREACH).(*attrs.MP)
	mp.AS = afi.AS_IPV4_UNICAST
	mpp := attrs.NewMPPrefixes(mp).(*attrs.MPPrefixes)
	mpp.Prefixes = []nlri.Prefix{p4}
	mp.Value = mpp
	m.Update.AddUnreach(p6)
	assert.ElementsMatch(t, []nlri.Prefix{p4, p6}, m.Update.AllUnreach())
}
