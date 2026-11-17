package attrs

import (
	"bytes"
	"testing"

	"github.com/bgpfix/bgpfix/caps"
	"github.com/bgpfix/bgpfix/meta"
)

// attrValue strips the attribute header from b
func attrValue(b []byte) []byte {
	if len(b) < 3 {
		return nil
	} else if b[0]&0x10 != 0 {
		return b[4:]
	}
	return b[3:]
}

// extended communities must survive a re-marshal bit-for-bit
func TestExtcomRemarshal(t *testing.T) {
	for _, in := range [][]byte{
		{0x08, 0x00, 1, 2, 3, 4, 5, 6}, // REDIRECT_NH
		{0x08, 0x05, 1, 2, 3, 4, 5, 6}, // unknown subtype of 0x08
		{0x48, 0x01, 1, 2, 3, 4, 5, 6},
		{0x80, 0x07, 1, 2, 3, 4, 5, 6}, // FLOW_ACTION
		{0x80, 0x09, 1, 2, 3, 4, 5, 6}, // FLOW_DSCP
	} {
		at := NewAttr(ATTR_EXT_COMMUNITY)
		if err := at.Unmarshal(in, caps.Caps{}, meta.Meta{}); err != nil {
			t.Fatal(err)
		}
		if out := attrValue(at.Marshal(nil, caps.Caps{}, meta.Meta{})); !bytes.Equal(in, out) {
			t.Errorf("in=%x out=%x json=%s", in, out, at.ToJSON(nil))
		}
	}
}

// malformed Flowspec rules (RFC 8955 4.2) must be rejected, not rewritten into other rules
func TestFlowspecMalformed(t *testing.T) {
	for name, val := range map[string][]byte{
		"empty component": {0x00, 0x01, 0x85, 0x00, 0x00, 0x08,
			0x05, 0x06, 0x81, 0x01, 0x04, 0x81, 0x50, // PORT_DST: !=129, ==4, ==80
			0x03}, // PROTO: no operators
		"duplicate component": {0x00, 0x01, 0x85, 0x00, 0x00, 0x0b,
			0x01, 0x08, 10, // DST 10.0.0.0/8
			0x01, 0x18, 192, 0, 2, // DST 192.0.2.0/24
			0x03, 0x81, 6}, // PROTO == 6
		"wrong order": {0x00, 0x01, 0x85, 0x00, 0x00, 0x07,
			0x03, 0x81, 6, // PROTO == 6
			0x01, 0x08, 10}, // DST 10.0.0.0/8
	} {
		at := NewAttr(ATTR_MP_REACH)
		if err := at.Unmarshal(val, caps.Caps{}, meta.Meta{}); err == nil {
			t.Errorf("%s: accepted: %s", name, at.ToJSON(nil))
		}
	}
}
