package msg

import (
	"bytes"
	"net/netip"
	"strconv"
	"testing"

	"github.com/bgpfix/bgpfix/attrs"
	"github.com/bgpfix/bgpfix/caps"
	"github.com/bgpfix/bgpfix/nlri"
)

// buildIPv6UpdateWire builds a wire-format UPDATE with ORIGIN/AS_PATH/MED
// and an MP_REACH carrying n IPv6 prefixes.
func buildIPv6UpdateWire(tb testing.TB, n int) []byte {
	tb.Helper()

	cps := caps.Caps{}
	m := NewMsg()
	m.Switch(UPDATE)
	u := &m.Update

	u.Attrs.Use(attrs.ATTR_ORIGIN).(*attrs.Origin).Origin = 0
	u.Attrs.Use(attrs.ATTR_ASPATH).(*attrs.Aspath).Set([]uint32{65001, 65002, 65003})
	u.Attrs.Use(attrs.ATTR_MED).(*attrs.U32).Val = 100

	prefixes := make([]nlri.Prefix, 0, n)
	base := netip.MustParseAddr("2001:db8::")
	as16 := base.As16()
	for i := range n {
		as16[7] = byte(i >> 8)
		as16[8] = byte(i)
		p, err := netip.AddrFrom16(as16).Prefix(64)
		if err != nil {
			tb.Fatal(err)
		}
		prefixes = append(prefixes, nlri.FromPrefix(p))
	}
	u.AddReach(prefixes...)

	mpp := u.ReachMP().Value.(*attrs.MPPrefixes)
	mpp.NextHop = netip.MustParseAddr("2001:db8::1")

	if err := m.Marshal(cps); err != nil {
		tb.Fatal(err)
	}

	var buf bytes.Buffer
	if _, err := m.WriteTo(&buf); err != nil {
		tb.Fatal(err)
	}
	return buf.Bytes()
}

// BenchmarkRelay simulates bgpipe's relay hot path: parse, a stage
// touches the message (Edit), re-marshal for forwarding.
func BenchmarkRelay(b *testing.B) {
	for _, n := range []int{1, 8, 64} {
		b.Run(strconv.Itoa(n)+"prefixes", func(b *testing.B) {
			wire := buildIPv6UpdateWire(b, n)
			cps := caps.Caps{}
			m := NewMsg() // one pooled msg reused across iterations, like Pipe.GetMsg/PutMsg

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				m.Reset()
				if _, err := m.FromBytes(wire); err != nil {
					b.Fatal(err)
				}
				if err := m.Parse(cps); err != nil {
					b.Fatal(err)
				}
				m.Edit() // simulate a stage touching the message
				if err := m.Marshal(cps); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
