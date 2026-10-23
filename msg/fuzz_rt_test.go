package msg

import (
	"bytes"
	stdjson "encoding/json"
	"regexp"
	"testing"

	"github.com/bgpfix/bgpfix/meta"
)

// FuzzUpdateRoundtrip checks that wire -> JSON -> wire -> JSON is a fixed point,
// ie. that JSON editing (exec, websocket, ...) never silently alters a message.
func FuzzUpdateRoundtrip(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte, flags byte) {
		if len(data) == 0 {
			return
		}
		cps := fuzzCaps(flags)
		m := NewMsg()
		m.Dir = meta.DIR_R
		hdr := make([]byte, HEADLEN, HEADLEN+len(data))
		copy(hdr, BgpMarker)
		l := HEADLEN + len(data) - 1
		hdr[16], hdr[17], hdr[18] = byte(l>>8), byte(l), byte(UPDATE)
		if _, err := m.FromBytes(append(hdr, data[1:]...)); err != nil {
			return
		}
		if err := m.Parse(cps); err != nil {
			return
		}
		js1 := append([]byte(nil), m.GetJSON()...)
		if !stdjson.Valid(js1) {
			t.Fatalf("invalid JSON: %s", js1)
		}

		// NB: an unknown Flowspec component swallows the rest of the rule (known)
		if bytes.Contains(js1, []byte(`"FlowType(`)) {
			return
		}

		// NB: skip inputs that are not stable under a plain in-memory re-marshal
		// (eg. Flowspec components out of order or empty, which Marshal normalizes; known)
		m.Edit()
		if err := m.Marshal(cps); err != nil {
			return
		}
		mc := NewMsg()
		mc.Dir = meta.DIR_R
		wb := append(append(append([]byte(nil), BgpMarker...), byte(m.Len()>>8), byte(m.Len()), byte(m.Type)), m.Data...)
		if _, err := mc.FromBytes(wb); err != nil || mc.Parse(cps) != nil {
			return
		}
		if !bytes.Equal(stripTime(js1), stripTime(mc.GetJSON())) {
			return
		}

		m2 := NewMsg()
		if err := m2.FromJSON(js1); err != nil {
			t.Fatalf("FromJSON(ToJSON()) failed: %v\n%s", err, js1)
		}
		if err := m2.Marshal(cps); err != nil {
			t.Fatalf("Marshal after FromJSON failed: %v\n%s", err, js1)
		}

		// parse the re-marshaled wire again
		raw := make([]byte, 0, m2.Len())
		raw = append(raw, BgpMarker...)
		n := m2.Len()
		raw = append(raw, byte(n>>8), byte(n), byte(m2.Type))
		raw = append(raw, m2.Data...)
		m3 := NewMsg()
		m3.Dir = meta.DIR_R
		if _, err := m3.FromBytes(raw); err != nil {
			t.Fatalf("FromBytes of re-marshaled: %v\n%s", err, js1)
		}
		if err := m3.Parse(cps); err != nil {
			t.Fatalf("Parse of re-marshaled: %v\n%s", err, js1)
		}
		js2 := m3.GetJSON()
		if !bytes.Equal(stripTime(js1), stripTime(js2)) {
			t.Fatalf("JSON not a fixed point:\n%s\n%s", js1, js2)
		}
	})
}

var flagsRe = regexp.MustCompile(`"flags":"[A-Z0-9]*"`)

// stripTime drops the leading ["R",seq,"time", prefix, so only the body is compared;
// the extended-length flag X is dropped too, as Marshal sets it only when needed.
func stripTime(js []byte) []byte {
	i := bytes.Index(js, []byte(`"UPDATE"`))
	if i < 0 {
		return js
	}
	return flagsRe.ReplaceAllFunc(js[i:], func(b []byte) []byte {
		return bytes.ReplaceAll(b, []byte("X"), nil)
	})
}
