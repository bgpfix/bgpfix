// NB: excluded from -race: Pipe.Stop() closes the inputs under active writers.
//go:build !race

package speaker

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/bgpfix/bgpfix/caps"
	"github.com/bgpfix/bgpfix/meta"
	"github.com/bgpfix/bgpfix/msg"
	"github.com/bgpfix/bgpfix/pipe"
)

func peerOpen(asn uint32, hold uint16, id string) *msg.Msg {
	m := msg.NewMsg().Switch(msg.OPEN)
	m.Open.Caps.Init()
	m.Open.SetASN(asn)
	m.Open.HoldTime = hold
	m.Open.Identifier = netip.MustParseAddr(id)
	m.Marshal(caps.Caps{})
	return m
}

func ka() *msg.Msg {
	m := msg.NewMsg()
	m.Type = msg.KEEPALIVE
	m.Data = []byte{}
	return m
}

func drain(l *pipe.Line) {
	for m := range l.Out {
		_ = m
	}
}

func setup(t *testing.T, hold int) (*pipe.Pipe, *Speaker) {
	p := pipe.NewPipe(context.Background())
	p.Options.Logger = nil
	p.Options.StopTimeout = 100 * time.Millisecond
	spk := NewSpeaker(context.Background())
	spk.Options.Logger = nil
	spk.Options.LocalHoldTime = hold
	if err := spk.Attach(p, meta.DIR_R); err != nil { // up = p.R (to peer), down = p.L (from peer)
		t.Fatal(err)
	}
	return p, spk
}

// Peer sends a valid OPEN (hold=3) but never a KEEPALIVE: no timer is armed before ESTABLISHED,
// so the session (and the one-session bgpipe process) hangs forever.
func TestRegress_NoTimerBeforeEstablished(t *testing.T) {
	p, _ := setup(t, 3)
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	go drain(p.L)
	go drain(p.R)
	p.L.WriteMsg(peerOpen(65001, 3, "1.1.1.1"))

	select {
	case <-p.Ctx.Done():
		t.Logf("ok: session torn down: %v", context.Cause(p.Ctx))
	case <-time.After(10 * time.Second):
		t.Errorf("peer sent OPEN (hold=3s) and then nothing; session still alive after 10s (no OpenConfirm hold timer)")
	}
	p.Stop()
}

// Options.RemoteId and Options.RemoteCaps are documented as enforced, but never checked.
func TestRegress_RemoteIdIgnored(t *testing.T) {
	p, spk := setup(t, 90)
	spk.Options.RemoteId = netip.MustParseAddr("192.0.2.1")
	var est = make(chan struct{}, 1)
	p.Options.OnEstablished(func(ev *pipe.Event) bool { est <- struct{}{}; return false })
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	go drain(p.L)
	go drain(p.R)
	p.L.WriteMsg(peerOpen(65001, 90, "203.0.113.66"))
	time.Sleep(50 * time.Millisecond)
	p.L.WriteMsg(ka())
	select {
	case <-est:
		t.Errorf("session ESTABLISHED with peer id 203.0.113.66 despite Options.RemoteId=192.0.2.1")
	case <-p.Ctx.Done():
		t.Logf("ok: rejected: %v", context.Cause(p.Ctx))
	case <-time.After(3 * time.Second):
		t.Logf("not established")
	}
	p.Stop()
}
