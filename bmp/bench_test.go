package bmp

import (
	"bytes"
	"context"
	"net/netip"
	"os"
	"testing"

	"github.com/bgpfix/bgpfix/caps"
	"github.com/bgpfix/bgpfix/mrt"
	"github.com/bgpfix/bgpfix/msg"
	"github.com/bgpfix/bgpfix/pipe"
)

// loadRM returns Route Monitoring messages built from the UPDATEs in a real MRT file.
// NB: uses local test data in ../../test, skips if not available
func loadRM(tb testing.TB) (rms [][]byte) {
	raw, err := os.ReadFile("../../test/updates.20230301.0000.mrt")
	if err != nil {
		tb.Skip(err)
	}
	mr, m, b := mrt.NewMrt(), msg.NewMsg(), NewBmp()
	var buf bytes.Buffer
	for len(raw) > 0 && len(rms) < 100_000 {
		mr.Reset()
		n, err := mr.FromBytes(raw)
		if err != nil {
			tb.Fatal(err)
		}
		raw = raw[n:]
		if mr.Parse() != nil || !mr.Type.IsBGP4() || mr.Bgp4.ToMsg(m.Reset(), true) != nil || m.Type != msg.UPDATE {
			continue
		}
		buf.Reset()
		m.WriteTo(&buf)

		b.Reset()
		b.Type = MSG_ROUTE_MONITORING
		b.Peer.Address = mr.Bgp4.PeerIP
		if b.Peer.Address.Is6() {
			b.Peer.Flags |= PEER_FLAG_V6
		}
		b.Peer.AS = mr.Bgp4.PeerAS
		b.Peer.ID = 0x0a000001
		b.Peer.Time = mr.Time
		b.BgpData = buf.Bytes()
		if err := b.Marshal(); err != nil {
			tb.Fatal(err)
		}
		rms = append(rms, append([]byte(nil), b.Bytes()...))
	}
	return
}

// BenchmarkReader measures the Route Monitoring path, up to the pipe input
func BenchmarkReader(b *testing.B) {
	rms := loadRM(b)
	p := pipe.NewPipe(context.Background())
	p.Options.Logger = nil
	if err := p.Start(); err != nil {
		b.Fatal(err)
	}
	drop := func(m *msg.Msg) bool { return false } // NB: returns m to the pool

	for _, notags := range []bool{false, true} {
		name := "tags"
		if notags {
			name = "notags"
		}
		b.Run(name, func(b *testing.B) {
			br := NewReader(p, nil)
			br.NoTags = notags
			b.ReportAllocs()
			for i := 0; b.Loop(); i++ {
				if _, err := br.WriteFunc(rms[i%len(rms)], drop); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkFromMsg measures the BMP export path: BGP message to Route Monitoring
func BenchmarkFromMsg(b *testing.B) {
	rms := loadRM(b)
	var ms []*msg.Msg
	for _, rm := range rms[:1000] {
		bm, m := NewBmp(), msg.NewMsg()
		bm.FromBytes(rm)
		m.FromBytes(bm.BgpData)
		m.CopyData()
		pipe.UseTags(m)["PEER_IP"] = bm.Peer.Address.String()
		ms = append(ms, m)
	}
	var cps caps.Caps
	cps.Use(caps.CAP_AS4)
	bm := NewBmp()
	b.ReportAllocs()
	for i := 0; b.Loop(); i++ {
		bm.Reset()
		if bm.FromMsg(ms[i%len(ms)], cps) != nil || bm.Marshal() != nil {
			b.Fatal("FromMsg")
		}
	}
}

// BenchmarkOpenBmp measures parsing the OpenBMP header of a RouteViews-like record
func BenchmarkOpenBmp(b *testing.B) {
	o := NewOpenBmp()
	o.CollectorName, o.RouterName = "bmp01", "route-views2"
	o.RouterIP = netip.MustParseAddr("192.0.2.1")
	o.Data = loadRM(b)[0]
	if err := o.Marshal(); err != nil {
		b.Fatal(err)
	}
	raw := append([]byte(nil), o.buf...)
	b.ReportAllocs()
	for b.Loop() {
		o.Reset()
		if _, err := o.FromBytes(raw); err != nil {
			b.Fatal(err)
		}
	}
}
