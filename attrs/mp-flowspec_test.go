package attrs

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/bgpfix/bgpfix/caps"
)

func TestFlowPrefix6(t *testing.T) {
	tests := []struct {
		buf   []byte
		json  string
		n     int
		iserr bool
	}{
		{[]byte{0x20, 0x00, 0x20, 0x01, 0x0d, 0xb8, 0xbe, 0xef}, `"2001:db8::/32"`, 6, false},                   // rfc8956/3.8.1 dst
		{[]byte{0x68, 0x40, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbe, 0xef}, `"::1234:5678:9a00:0/64-104"`, 7, false}, // rfc8956/3.8.1 src
		{[]byte{0x40, 0x68, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbe, 0xef}, `"::1234:5678:9a00:0/104-64"`, 7, true},  // rfc8956/3.8.1 src error
		{[]byte{0x68, 0x41, 0x24, 0x68, 0xac, 0xf1, 0x34, 0xbe, 0xef}, `"::1234:5678:9a00:0/65-104"`, 7, false}, // rfc8956/3.8.2 src
	}
	var cps caps.Caps
	fp := NewFlowPrefix6(FLOW_SRC)
	for ti, tt := range tests {
		t.Run(fmt.Sprintf("tests[%d]", ti), func(t *testing.T) {
			n, err := fp.Unmarshal(tt.buf, cps)
			if err != nil {
				if !tt.iserr {
					t.Errorf("FlowPrefix6 Unmarshal error = %v, iserr %v", err, tt.iserr)
				}
				return
			}
			if json := string(fp.ToJSON(nil)); json != tt.json {
				t.Errorf("FlowPrefix6 json = '%s', want '%s'", json, tt.json)
			}
			if n != tt.n {
				t.Errorf("FlowPrefix6 n = %d, want %d", n, tt.n)
			}
			buf := fp.Marshal(nil, cps)
			if !bytes.Equal(tt.buf[:tt.n], buf) {
				t.Errorf("FlowPrefix6 Marshal buf = '%x', want '%x'", buf, tt.buf[:tt.n])
			}
		})
	}
}
