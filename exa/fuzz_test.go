package exa

import (
	"testing"

	"github.com/bgpfix/bgpfix/caps"
	"github.com/bgpfix/bgpfix/msg"
)

func FuzzExa(f *testing.F) {
	f.Add("neighbor 192.0.2.1 announce route 10.0.0.0/8 next-hop 192.0.2.1 as-path [ 65001 65002 ] community [ 65000:1 ] large-community [ 1:2:3 ] origin igp med 10 local-preference 100")
	f.Add("neighbor 2001:db8::1 withdraw route 2001:db8::/32")
	f.Fuzz(func(t *testing.T, line string) {
		x, err := NewExaLine(line)
		if err != nil {
			return
		}
		_ = x.String()
		m := msg.NewMsg()
		if x.ToMsg(m) != nil {
			return
		}
		m.Marshal(caps.Caps{})
		m.GetJSON()
		y := NewExa()
		for range y.IterMsg(m) {
			_ = y.String()
		}
	})
}
