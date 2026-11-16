package exa

import (
	"testing"

	"github.com/bgpfix/bgpfix/caps"
	"github.com/bgpfix/bgpfix/msg"
)

func FuzzExa(f *testing.F) {
	f.Add("neighbor 192.0.2.1 announce route 10.0.0.0/8 next-hop 192.0.2.1 as-path [ 65001 65002 ] community [ 65000:1 ] large-community [ 1:2:3 ] origin igp med 10 local-preference 100")
	f.Add("announce route 10.0.0.0/8 next-hop self extended-community [target:65000:1 origin:192.0.2.1:2 0x0002fde800000001] atomic-aggregate aggregator (65000:192.0.2.9) originator-id 192.0.2.7 cluster-list [192.0.2.8]")
	f.Add("announce attributes next-hop 10.0.0.1 med 5 nlri 10.0.0.0/24 10.0.1.0/24")
	f.Add("announce flow route { match { destination 10.0.0.3/32; tcp-flags [ syn !ack =syn+ack ]; packet-length >=100&<=200; port [ =80 true ]; } then { redirect 65000:100; action sample-terminal; rate-limit 9600 packets; mark 3; copy 192.0.2.1; } }")
	f.Add("announce flow route source 2001:db8:1::/64/32 flow-label =5 next-header udp discard")
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
