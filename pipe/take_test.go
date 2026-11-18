package pipe

import (
	"context"
	"testing"
	"time"

	"github.com/bgpfix/bgpfix/meta"
	"github.com/bgpfix/bgpfix/msg"
)

// a callback takes messages, another goroutine sends them again later: all arrive, intact
func TestTake(t *testing.T) {
	p := NewPipe(context.Background())
	held := make(chan *msg.Msg, 1000)
	again := p.Options.AddInput(meta.DIR_R)
	p.Options.OnMsg(func(m *msg.Msg) bool {
		mx := UseContext(m)
		if mx.Input == again {
			return true // sent again: pass
		}
		(&m.Tags).Set("held", "yes")
		Take(m)
		held <- m
		return false
	}, meta.DIR_R)
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}

	go func() {
		for m := range held {
			time.Sleep(time.Microsecond)
			again.WriteMsg(m)
		}
	}()

	const n = 1000
	go func() {
		for range n {
			m := p.GetMsg()
			m.FromBytes(append(append([]byte{}, msg.BgpMarker...), 0, 19, byte(msg.KEEPALIVE)))
			m.CopyData()
			p.R.WriteMsg(m)
		}
	}()

	for i := range n {
		select {
		case m := <-p.R.Out:
			if m.Type != msg.KEEPALIVE || m.Tags.Get("held") != "yes" {
				t.Fatalf("message %d: %s", i, m)
			}
			p.PutMsg(m)
		case <-time.After(5 * time.Second):
			t.Fatalf("got %d of %d messages", i, n)
		}
	}
	close(held)
	p.Stop()
}
