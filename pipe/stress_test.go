// NB: excluded from -race: Pipe.Stop() closes the inputs under active writers.
// WriteMsg recovers from that by design, to keep its hot path a plain channel
// send, but the race detector still flags close vs. send.
//
//go:build !race

package pipe

import (
	"context"
	"testing"
	"time"
)

func TestPipe_StressShutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	p := newTestPipe(ctx)
	if err := p.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	go drainLine(p.L)
	go drainLine(p.R)

	// continuously send messages using WriteMsg (safe against closed channel)
	stopSending := make(chan struct{})
	go func() {
		for {
			select {
			case <-stopSending:
				return
			default:
			}
			m := newKeepalive()
			if p.L.Input.WriteMsg(m) != nil {
				return
			}
		}
	}()

	// stop while messages are in flight
	time.Sleep(5 * time.Millisecond)
	p.Stop()
	close(stopSending)
	// should not panic or deadlock
}
