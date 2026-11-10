package bmp

import (
	"context"
	"testing"

	"github.com/bgpfix/bgpfix/caps"
	"github.com/bgpfix/bgpfix/meta"
	"github.com/bgpfix/bgpfix/msg"
	"github.com/bgpfix/bgpfix/pipe"
)

func FuzzBmpReader(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte, obmp bool) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		p := pipe.NewPipe(ctx)
		p.Options.Logger = nil
		p.Options.Caps = false
		in := p.Options.AddInput(meta.DIR_R)
		br := NewReader(p, in)
		br.OpenBMP = obmp
		if err := p.Start(); err != nil {
			t.Fatal(err)
		}
		done := make(chan struct{})
		go func() {
			defer close(done)
			var cps caps.Caps
			for m := range p.R.Out {
				if m.Parse(cps) == nil {
					m.GetJSON()
				}
			}
		}()
		br.Write(data)
		p.Stop()
		<-done

		b := NewBmp()
		ob := NewOpenBmp()
		m := msg.NewMsg()
		br.FromBytes(data, m, b, ob)
		if _, err := b.FromBytes(data); err == nil {
			b.CopyData()
			b.Marshal()
			if b.Type == MSG_ROUTE_MONITORING {
				m2 := msg.NewMsg()
				if _, err := m2.FromBytes(b.BgpData); err == nil {
					ob2 := NewOpenBmp()
					ob2.FromBmp(b, m2)
					ob2.Marshal()
				}
			}
		}
	})
}
