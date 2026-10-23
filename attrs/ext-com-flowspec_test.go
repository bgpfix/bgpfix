package attrs

import (
	stdjson "encoding/json"
	"math"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestExtcomFlowRate_NonFinite checks that NaN/Inf traffic rates give valid JSON that round-trips.
func TestExtcomFlowRate_NonFinite(t *testing.T) {
	for _, bits := range []uint32{0x7fc00000, 0x7f800000, 0xff800000, 0x3f800000} {
		for _, id := range []uint16{0, 7} {
			e := &ExtcomFlowRate{Id: id}
			require.NoError(t, e.Unmarshal(uint64(id)<<32|uint64(bits)))
			js := e.ToJSON(nil)
			require.True(t, stdjson.Valid(js), "%s", js)

			var got ExtcomFlowRate
			require.NoError(t, got.FromJSON(js), "%s", js)
			require.Equal(t, id, got.Id)
			require.Equal(t, math.IsNaN(float64(e.Rate)), math.IsNaN(float64(got.Rate)))
			if !math.IsNaN(float64(e.Rate)) {
				require.Equal(t, e.Rate, got.Rate)
			}
		}
	}
}
