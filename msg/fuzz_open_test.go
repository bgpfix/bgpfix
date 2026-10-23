package msg

import (
	"testing"

	"github.com/bgpfix/bgpfix/caps"
)

func fuzzOpen(body []byte) *Msg {
	hdr := make([]byte, HEADLEN, HEADLEN+len(body))
	copy(hdr, BgpMarker)
	l := HEADLEN + len(body)
	hdr[16], hdr[17], hdr[18] = byte(l>>8), byte(l), byte(OPEN)
	m := NewMsg()
	if _, err := m.FromBytes(append(hdr, body...)); err != nil {
		return nil
	}
	if err := m.Parse(caps.Caps{}); err != nil {
		return nil
	}
	return m
}

// FuzzOpen parses two OPEN bodies, then runs the capability negotiation as
// pipe.checkEstablished() does, and marshals the results back.
func FuzzOpen(f *testing.F) {
	hdr := []byte{4, 0xfd, 0xe8, 0, 90, 1, 2, 3, 4}
	open := func(params ...byte) []byte {
		return append(append([]byte(nil), hdr...), append([]byte{byte(len(params))}, params...)...)
	}
	capv := func(code byte, val ...byte) []byte {
		return append([]byte{2, byte(len(val) + 2), code, byte(len(val))}, val...)
	}
	cat := func(parts ...[]byte) []byte {
		var o []byte
		for _, p := range parts {
			o = append(o, p...)
		}
		return o
	}
	good := open(cat(
		capv(1, 0, 1, 0, 1), capv(65, 0, 0, 0xfd, 0xe8), capv(69, 0, 1, 1, 3),
		capv(5, 0, 1, 0, 1, 0, 2), capv(73, 4, 'b', 'g', 'p', 'd', 3, 'n', 'e', 't'), capv(9, 4), capv(2), capv(6))...)
	f.Add(good, good)
	f.Add(open(capv(73, 2, 'a', 'b')...), good)
	f.Add(open(capv(69, 0, 1, 1, 1)...), open(capv(69, 0, 1, 1, 2)...))
	f.Add(append(append([]byte(nil), hdr...), 255, 255, 0, 3, 2, 0, 0), good) // extended params, truncated
	f.Fuzz(func(t *testing.T, a, b []byte) {
		ma, mb := fuzzOpen(a), fuzzOpen(b)
		if ma == nil || mb == nil {
			return
		}
		ra, la := &ma.Open, &mb.Open

		var common caps.Caps
		ra.Caps.Each(func(i int, cc caps.Code, rcap caps.Cap) {
			lcap := la.Caps.Get(cc)
			if lcap == nil {
				return
			}
			if icap := rcap.Intersect(lcap); icap != nil {
				common.Set(cc, icap)
			} else {
				common.Set(cc, rcap)
			}
		})
		common.ToJSON(nil)

		// use the negotiated caps to parse and re-marshal an UPDATE-ish message
		for _, o := range []*Open{ra, la} {
			o.GetASN()
			o.Msg.GetJSON()
			if err := o.MarshalCaps(); err != nil {
				continue
			}
			o.Msg.Edit()
			o.Msg.Marshal(common)
		}
	})
}
