package filter

import (
	"testing"

	"github.com/bgpfix/bgpfix/msg"
)

func FuzzFilter(f *testing.F) {
	for _, s := range []string{"prefix ~ 8.0.0.0/8", "aspath[0] == 65001 && origin == 666", "com ~ 65000:1 || !(nexthop == 1.2.3.4)", "tag[foo] == bar", "aspath ~ \"^65001 .* 666$\"", "lcom ~ 1:2:3", "update && af == ipv6/unicast", "time > 2023-01-01"} {
		f.Add(s)
	}
	m := msg.NewMsg()
	if err := m.FromJSON([]byte(`["R",1,"2023-01-01T00:00:00.000","UPDATE",{"reach":["1.0.0.0/8","2001:db8::/32"],"attrs":{"ORIGIN":{"flags":"T","value":"IGP"},"ASPATH":{"flags":"T","value":[65001,[1,2],666]},"NEXTHOP":{"flags":"T","value":"1.2.3.4"},"COMMUNITY":{"flags":"OT","value":["65000:1"]},"LARGE_COMMUNITY":{"flags":"OT","value":["1:2:3"]}}},{"foo":"bar"}]`)); err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, s string) {
		flt, err := NewFilter(s)
		if err != nil {
			return
		}
		ev := NewEval(true)
		ev.SetMsg(m)
		ev.Run(flt)
	})
}
