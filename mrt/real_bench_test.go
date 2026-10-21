package mrt

import (
	"bytes"
	"os"
	"testing"

	"github.com/bgpfix/bgpfix/caps"
	"github.com/bgpfix/bgpfix/msg"
)

// loadWire returns wire-format BGP messages (UPDATEs only) from a real MRT file.
// NB: uses local test data in ../../test, skips if not available
func loadWire(tb testing.TB) (wire [][]byte, js [][]byte) {
	raw, err := os.ReadFile("../../test/updates.20230301.0000.mrt")
	if err != nil {
		tb.Skip(err)
	}
	mr := NewMrt()
	m := msg.NewMsg()
	for len(raw) > 0 {
		mr.Reset()
		n, err := mr.FromBytes(raw)
		if err != nil {
			tb.Fatal(err)
		}
		raw = raw[n:]
		if mr.Parse() != nil || !mr.Type.IsBGP4() || mr.Bgp4.ToMsg(m.Reset(), true) != nil || m.Type != msg.UPDATE {
			continue
		}
		var buf bytes.Buffer
		m.WriteTo(&buf)
		wire = append(wire, buf.Bytes())
		var cps caps.Caps
		cps.Use(caps.CAP_AS4)
		if m.Parse(cps) == nil {
			js = append(js, append([]byte(nil), m.GetJSON()...))
		}
	}
	return
}

// BenchmarkReal measures common message paths on real UPDATEs
func BenchmarkReal(b *testing.B) {
	wire, js := loadWire(b)
	b.Logf("%d wire, %d json", len(wire), len(js))
	var cps caps.Caps
	cps.Use(caps.CAP_AS4)
	m := msg.NewMsg()
	b.Run("parse", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; b.Loop(); i++ {
			m.Reset()
			m.FromBytes(wire[i%len(wire)])
			m.Parse(cps)
		}
	})
	b.Run("parse+json", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; b.Loop(); i++ {
			m.Reset()
			m.FromBytes(wire[i%len(wire)])
			m.Parse(cps)
			m.GetJSON()
		}
	})
	b.Run("parse+edit+marshal", func(b *testing.B) {
		b.ReportAllocs()
		var out bytes.Buffer
		for i := 0; b.Loop(); i++ {
			m.Reset()
			m.FromBytes(wire[i%len(wire)])
			m.Parse(cps)
			m.Edit()
			m.Marshal(cps)
			out.Reset()
			m.WriteTo(&out)
		}
	})
	b.Run("fromjson", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; b.Loop(); i++ {
			m.Reset()
			m.FromJSON(js[i%len(js)])
		}
	})
}
