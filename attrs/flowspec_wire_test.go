package attrs

import (
	"bytes"
	"testing"

	"github.com/bgpfix/bgpfix/afi"
	"github.com/bgpfix/bgpfix/caps"
	"github.com/bgpfix/bgpfix/dir"
	"github.com/bgpfix/bgpfix/nlri"
	"github.com/stretchr/testify/require"
)

// TestFlowGeneric_Wire tests numeric and bitmask operators
func TestFlowGeneric_Wire(t *testing.T) {
	var cps caps.Caps

	tests := []struct {
		name string
		buf  []byte
		ops  []FlowOp
		vals []uint64
	}{
		{
			name: "single equals",
			buf:  []byte{0x81, 0x06}, // last=1, ==, len=1, val=6
			ops:  []FlowOp{FLOW_OP_LAST | FLOW_OP_EQ},
			vals: []uint64{6},
		},
		{
			name: "range 80-443",
			buf:  []byte{0x03, 0x50, 0x91, 0x01, 0xBB}, // >=80 (len=1), last=1 <=443 (len=2)
			ops:  []FlowOp{FLOW_OP_GT | FLOW_OP_EQ, FLOW_OP_LAST | FLOW_OP_LT | FLOW_OP_EQ | 0x10},
			vals: []uint64{80, 443},
		},
		{
			name: "bitmask TCP SYN",
			buf:  []byte{0x81, 0x02}, // last=1, match=1, len=1, val=0x02
			ops:  []FlowOp{FLOW_OP_LAST | FLOW_OP_MATCH | FLOW_OP_IS_BITMASK},
			vals: []uint64{0x02},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fg := NewFlowGeneric(FLOW_PORT).(*FlowGeneric)
			if tt.name == "bitmask TCP SYN" {
				fg.Type = FLOW_TCP_FLAGS
			}

			n, err := fg.Unmarshal(tt.buf, cps)
			require.NoError(t, err)
			require.Equal(t, len(tt.buf), n)
			require.Len(t, fg.Op, len(tt.ops))
			require.Len(t, fg.Val, len(tt.vals))

			for i := range tt.vals {
				require.Equal(t, tt.vals[i], fg.Val[i])
			}

			// round-trip
			buf := fg.Marshal(nil, cps)
			require.Equal(t, tt.buf, buf)
		})
	}
}

// TestFlowPrefix4_Wire tests IPv4 flowspec prefix encoding
func TestFlowPrefix4_Wire(t *testing.T) {
	var cps caps.Caps

	tests := []struct {
		name   string
		buf    []byte
		prefix string
	}{
		{"10.0.0.0/8", []byte{0x08, 0x0a}, "10.0.0.0/8"},
		{"192.168.1.0/24", []byte{0x18, 0xc0, 0xa8, 0x01}, "192.168.1.0/24"},
		{"0.0.0.0/0", []byte{0x00}, "0.0.0.0/0"},
		{"10.20.30.40/32", []byte{0x20, 0x0a, 0x14, 0x1e, 0x28}, "10.20.30.40/32"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := NewFlowPrefix4(FLOW_DST).(*FlowPrefix4)
			n, err := fp.Unmarshal(tt.buf, cps)
			require.NoError(t, err)
			require.Equal(t, len(tt.buf), n)
			require.Equal(t, tt.prefix, fp.Prefix.String())

			// round-trip
			buf := fp.Marshal(nil, cps)
			require.Equal(t, tt.buf, buf)
		})
	}
}

// TestFlowPrefix6_Roundtrip tests IPv6 flowspec prefix round-trip
func TestFlowPrefix6_Roundtrip(t *testing.T) {
	var cps caps.Caps

	tests := []struct {
		name   string
		buf    []byte
		json   string
		wantN  int
		wantOK bool
	}{
		{
			name:   "simple /32",
			buf:    []byte{0x20, 0x00, 0x20, 0x01, 0x0d, 0xb8},
			json:   `"2001:db8::/32"`,
			wantN:  6,
			wantOK: true,
		},
		{
			name:   "with offset /64-104",
			buf:    []byte{0x68, 0x40, 0x12, 0x34, 0x56, 0x78, 0x9a},
			json:   `"::1234:5678:9a00:0/64-104"`,
			wantN:  7,
			wantOK: true,
		},
		{
			name:   "offset >= length (invalid)",
			buf:    []byte{0x40, 0x68, 0x12, 0x34, 0x56, 0x78, 0x9a},
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := NewFlowPrefix6(FLOW_SRC).(*FlowPrefix6)
			n, err := fp.Unmarshal(tt.buf, cps)

			if !tt.wantOK {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.wantN, n)

			// check JSON
			json := string(fp.ToJSON(nil))
			require.Equal(t, tt.json, json)

			// round-trip marshal
			buf := fp.Marshal(nil, cps)
			require.Equal(t, tt.buf[:tt.wantN], buf)
		})
	}
}

// TestMPFlowspec_RuleLength tests the NLRI length encoding (RFC8955)
func TestMPFlowspec_RuleLength(t *testing.T) {
	var cps caps.Caps

	tests := []struct {
		name     string
		nlriLen  int
		wantHead []byte
	}{
		{"short rule (< 240)", 100, []byte{100}},
		{"exact boundary (239)", 239, []byte{239}},
		{"extended length (240)", 240, []byte{0xf0, 0xf0}},
		{"extended length (500)", 500, []byte{0xf1, 0xf4}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create an MP attribute with flowspec
			mp := NewAttr(ATTR_MP_REACH).(*MP)
			mp.AS = afi.AS_IPV4_FLOWSPEC

			fs := NewMPFlowspec(mp).(*MPFlowspec)
			mp.Value = fs

			// Create a dummy rule that will marshal to the desired length
			// We use a raw flowvalue for precise control
			rawData := make([]byte, tt.nlriLen-1) // -1 for the type byte
			rule := FlowRule{
				FLOW_DST: &FlowRaw{Raw: rawData},
			}
			fs.Rules = []FlowRule{rule}

			// Marshal
			fs.Marshal(cps, dir.DIR_L)

			// Check the length header
			require.True(t, len(mp.Data) >= len(tt.wantHead))
			require.Equal(t, tt.wantHead, mp.Data[:len(tt.wantHead)])
		})
	}
}

// TestFlowspec_EmptyRule tests handling of empty flowspec rules
func TestFlowspec_EmptyRule(t *testing.T) {
	var cps caps.Caps

	mp := NewAttr(ATTR_MP_UNREACH).(*MP)
	mp.AS = afi.AS_IPV4_FLOWSPEC

	fs := NewMPFlowspec(mp).(*MPFlowspec)
	mp.Value = fs

	// Create valid prefix
	fp := &FlowPrefix4{}
	fp.Prefix, _ = nlri.FromString("10.0.0.0/8")

	// Empty rules should be skipped during marshal
	fs.Rules = []FlowRule{
		{}, // empty - should be skipped
		{FLOW_DST: fp},
		{}, // empty - should be skipped
	}

	fs.Marshal(cps, dir.DIR_L)

	// Parse back
	fs2 := NewMPFlowspec(mp).(*MPFlowspec)
	mp.Value = fs2
	err := fs2.Unmarshal(cps, dir.DIR_L)
	require.NoError(t, err)
	require.Len(t, fs2.Rules, 1) // only non-empty rule
}

// TestExtcomFlowRate_Wire tests flowspec rate limit extended community
func TestExtcomFlowRate_Wire(t *testing.T) {
	tests := []struct {
		name string
		raw  uint64
		id   uint16
		rate float32
	}{
		{"rate 0", 0x0000000000000000, 0, 0},
		{"rate 1000", 0x00000000447a0000, 0, 1000},
		{"rate with id", 0x0000000144fa0000, 1, 2000}, // id at bits 47-32
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			efr := NewExtcomFlowRate(EXTCOM_FLOW_RATE_BYTES).(*ExtcomFlowRate)
			err := efr.Unmarshal(tt.raw)
			require.NoError(t, err)
			require.Equal(t, tt.id, efr.Id)
			require.InDelta(t, tt.rate, efr.Rate, 0.1)

			// round-trip
			raw := efr.Marshal()
			require.Equal(t, tt.raw, raw)
		})
	}
}

// TestExtcomFlowAction_Wire tests flowspec action extended community
func TestExtcomFlowAction_Wire(t *testing.T) {
	tests := []struct {
		name     string
		raw      uint64
		terminal bool
		sample   bool
	}{
		{"none", 0x0000000000000000, false, false},
		{"terminal", 0x0000000000000001, true, false},
		{"sample", 0x0000000000000002, false, true},
		{"both", 0x0000000000000003, true, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			efa := NewExtcomFlowAction(EXTCOM_FLOW_ACTION).(*ExtcomFlowAction)
			err := efa.Unmarshal(tt.raw)
			require.NoError(t, err)
			require.Equal(t, tt.terminal, efa.Terminal)
			require.Equal(t, tt.sample, efa.Sample)

			// round-trip
			raw := efa.Marshal()
			require.Equal(t, tt.raw, raw)
		})
	}
}

// TestExtcomFlowDSCP_Wire tests flowspec DSCP marking extended community
func TestExtcomFlowDSCP_Wire(t *testing.T) {
	tests := []struct {
		name string
		raw  uint64
		dscp uint8
	}{
		{"dscp 0", 0x0000000000000000, 0},
		{"dscp 46 (EF)", 0x000000000000002e, 46},
		{"dscp 63 (max)", 0x000000000000003f, 63},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			efd := NewExtcomFlowDSCP(EXTCOM_FLOW_DSCP).(*ExtcomFlowDSCP)
			err := efd.Unmarshal(tt.raw)
			require.NoError(t, err)
			require.Equal(t, tt.dscp, efd.DSCP)

			// round-trip
			raw := efd.Marshal()
			require.Equal(t, tt.raw, raw)
		})
	}
}

// TestFlowGeneric_EdgeCases tests edge cases in FlowGeneric parsing
func TestFlowGeneric_EdgeCases(t *testing.T) {
	var cps caps.Caps

	t.Run("empty input", func(t *testing.T) {
		fg := NewFlowGeneric(FLOW_PORT).(*FlowGeneric)
		n, err := fg.Unmarshal([]byte{}, cps)
		// Empty input is valid - returns 0 ops
		require.NoError(t, err)
		require.Equal(t, 0, n)
		require.Len(t, fg.Op, 0)
	})

	t.Run("truncated value", func(t *testing.T) {
		fg := NewFlowGeneric(FLOW_PORT).(*FlowGeneric)
		// Op with len=2 but only 1 byte follows
		_, err := fg.Unmarshal([]byte{0x91}, cps) // len=2, but no value
		require.Error(t, err)
	})

	t.Run("4-byte value", func(t *testing.T) {
		fg := NewFlowGeneric(FLOW_PORT).(*FlowGeneric)
		// Op with len=4
		buf := []byte{0xa1, 0x00, 0x01, 0x00, 0x00} // last=1, ==, len=4, val=65536
		n, err := fg.Unmarshal(buf, cps)
		require.NoError(t, err)
		require.Equal(t, 5, n)
		require.Equal(t, uint64(65536), fg.Val[0])

		// round-trip
		out := fg.Marshal(nil, cps)
		require.Equal(t, buf, out)
	})
}

// TestMPFlowspec_JSON_Roundtrip tests JSON serialization
func TestMPFlowspec_JSON_Roundtrip(t *testing.T) {
	var cps caps.Caps

	// Build a flowspec rule
	mp := NewAttr(ATTR_MP_REACH).(*MP)
	mp.AS = afi.AS_IPV4_FLOWSPEC

	fs := NewMPFlowspec(mp).(*MPFlowspec)
	mp.Value = fs

	// Add a rule with destination prefix and port
	fp := &FlowPrefix4{}
	fp.Prefix, _ = nlri.FromString("10.0.0.0/8")

	fg := NewFlowGeneric(FLOW_PORT).(*FlowGeneric)
	fg.Op = []FlowOp{FLOW_OP_LAST | FLOW_OP_EQ}
	fg.Val = []uint64{80}

	rule := FlowRule{
		FLOW_DST:  fp,
		FLOW_PORT: fg,
	}
	fs.Rules = []FlowRule{rule}

	// Serialize to JSON - note: ToJSON outputs inner keys, not full object
	json1 := string(fs.ToJSON(nil))
	require.Contains(t, json1, `"DST"`)
	require.Contains(t, json1, `"PORT"`)

	// For FromJSON we need a full JSON object
	fullJson := "{" + json1 + "}"

	// Parse JSON back
	mp2 := NewAttr(ATTR_MP_REACH).(*MP)
	mp2.AS = afi.AS_IPV4_FLOWSPEC
	fs2 := NewMPFlowspec(mp2).(*MPFlowspec)
	mp2.Value = fs2

	err := fs2.FromJSON([]byte(fullJson))
	require.NoError(t, err)
	require.Len(t, fs2.Rules, 1)

	// Wire round-trip
	fs.Marshal(cps, dir.DIR_L)
	fs2.Marshal(cps, dir.DIR_L)
	require.True(t, bytes.Equal(mp.Data, mp2.Data))
}
