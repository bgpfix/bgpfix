package mrt

import (
	"context"
	"testing"

	"github.com/bgpfix/bgpfix/caps"
	"github.com/bgpfix/bgpfix/meta"
	"github.com/bgpfix/bgpfix/msg"
	"github.com/bgpfix/bgpfix/pipe"
)

func FuzzMrtReader(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		p := pipe.NewPipe(ctx)
		p.Options.Logger = nil
		p.Options.Caps = false
		in := p.Options.AddInput(meta.DIR_R)
		br := NewReader(p, in)
		if err := p.Start(); err != nil {
			t.Fatal(err)
		}
		done := make(chan struct{})
		go func() {
			defer close(done)
			var cps caps.Caps
			cps.Use(caps.CAP_AS4)
			for m := range p.R.Out {
				if m.Parse(cps) == nil {
					m.GetJSON()
					m.Edit()
					m.Marshal(cps)
				}
			}
		}()
		// feed in two chunks to exercise buffering
		h := len(data) / 2
		if _, err := br.Write(data[:h]); err == nil {
			br.Write(data[h:])
		}
		br.Flush(nil)
		p.Stop()
		<-done

		// stateless path too
		m := msg.NewMsg()
		br2 := NewReader(nil, nil)
		br2.FromBytes(data, m, nil)
	})
}
