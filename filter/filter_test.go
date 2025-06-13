package filter

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseExpressions(t *testing.T) {
	tests := []string{
		`af == ipv4/flowspec`,
		"prefix == 192.168.0.0/24",
		"as_path[-1] == 65001",
		// "community == 100:200",
		// `!(UPDATE && (as_origin == 39282 || !aspath[0] < 1000) && com ~ "11:22 \\\"22:34")`,
		`!(UPDATE && (as_origin == 39282 || !aspath[0] < 1000))`,
	}

	for ti, test := range tests {
		f, err := NewFilter(test)
		assert.NoError(t, err, "Test %d: %s", ti, test)
		t.Logf("#%d: %#v", ti, f)
	}
}
