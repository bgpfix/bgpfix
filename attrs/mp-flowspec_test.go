package attrs

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/bgpfix/bgpfix/caps"
)

func TestParseFlowPrefix6(t *testing.T) {
	tests := []struct {
		arg     []byte
		want    string
		wantN   int
		wantErr bool
	}{
		{[]byte{0x20, 0x00, 0x20, 0x01, 0x0d, 0xb8, 0xbe, 0xef}, `"2001:db8::/32"`, 6, false},                   // rfc8956/3.8.1 dst
		{[]byte{0x68, 0x40, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbe, 0xef}, `"::1234:5678:9a00:0/64-104"`, 7, false}, // rfc8956/3.8.1 src
		{[]byte{0x40, 0x68, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbe, 0xef}, `"::1234:5678:9a00:0/104-64"`, 7, true},  // rfc8956/3.8.1 src error
		{[]byte{0x68, 0x41, 0x24, 0x68, 0xac, 0xf1, 0x34, 0xbe, 0xef}, `"::1234:5678:9a00:0/65-104"`, 7, false}, // rfc8956/3.8.2 src
	}
	var cps caps.Caps
	for ti, tt := range tests {
		t.Run(fmt.Sprintf("tests[%d]", ti), func(t *testing.T) {
			got, gotN, err := ParseFlowPrefix6(0, tt.arg)
			if err != nil {
				if !tt.wantErr {
					t.Errorf("ParseFlowPrefix6() error = %v, wantErr %v", err, tt.wantErr)
				}
				return
			}
			if str := string(got.ToJSON(nil)); str != tt.want {
				t.Errorf("ParseFlowPrefix6() got = '%s', want '%s'", str, tt.want)
			}
			if gotN != tt.wantN {
				t.Errorf("ParseFlowPrefix6() gotN = %d, want %d", gotN, tt.wantN)
			}
			res := got.Marshal(nil, cps)
			if !bytes.Equal(tt.arg[:tt.wantN], res) {
				t.Errorf("Marshal() result = '%x', want '%x'", res, tt.arg[:tt.wantN])
			}
		})
	}
}
