// NB: excluded from -race: Pipe.Stop() closes the inputs under active writers.
//go:build !race

package pipe

import (
	"context"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bgpfix/bgpfix/caps"
	"github.com/bgpfix/bgpfix/filter"
	"github.com/bgpfix/bgpfix/meta"
	"github.com/bgpfix/bgpfix/msg"
)

func regressOpen(asn uint32) *msg.Msg {
	m := msg.NewMsg().Switch(msg.OPEN)
	m.Open.Caps.Init()
	m.Open.SetASN(asn)
	m.Open.HoldTime = 90
	m.Open.Identifier = netip.AddrFrom4([4]byte{10, 0, 0, byte(asn)})
	return m
}

func regressBadUpdate() *msg.Msg {
	m := msg.NewMsg()
	m.Type = msg.UPDATE
	m.Data = []byte{0xff, 0xff, 0xff} // unparseable
	return m
}

func doneWithin(f func(), d time.Duration) bool {
	ch := make(chan struct{})
	go func() { f(); close(ch) }()
	select {
	case <-ch:
		return true
	case <-time.After(d):
		return false
	}
}

// Stop() before Start(): Start() fails, and Wait() returns
func TestStopBeforeStart(t *testing.T) {
	p := newTestPipe(context.Background())
	p.Stop()
	err := p.Start()
	t.Logf("Start() after Stop() = %v", err)
	if !doneWithin(p.Wait, 2*time.Second) {
		t.Errorf("Pipe.Wait() hangs after Stop() before Start()")
	}
}

// concurrent Start() and Stop() always return
func TestStartStopRace(t *testing.T) {
	hangs := 0
	for i := 0; i < 2000 && hangs == 0; i++ {
		p := newTestPipe(context.Background())
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); p.Start() }()
		go func() { defer wg.Done(); p.Stop() }()
		if !doneWithin(wg.Wait, 2*time.Second) {
			hangs++
			t.Errorf("iteration %d: concurrent Start()/Stop() deadlocked", i)
		} else {
			go drainLine(p.L)
			go drainLine(p.R)
			p.Stop()
		}
	}
}

// an event handler can call Pipe.Stop()
func TestStopFromHandler(t *testing.T) {
	p := newTestPipe(context.Background())
	p.Options.OnEvent(func(ev *Event) bool {
		p.Stop()
		return false
	}, "custom/STOP_ME")
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	go drainLine(p.L)
	go drainLine(p.R)
	p.Event("custom/STOP_ME")
	if !doneWithin(p.Wait, 3*time.Second) {
		t.Errorf("Pipe.Stop() called from an event handler never returns; Pipe.Wait() hangs forever")
	}
}

// a full event queue (eg. EVENT_PARSE from a burst of malformed UPDATEs) must not
// deadlock handlers that emit events, even with a single event goroutine (GOMAXPROCS=1)
func TestEventQueueFull(t *testing.T) {
	old := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(old)

	p := newTestPipe(context.Background())
	p.Options.StopTimeout = 200 * time.Millisecond

	// a (slow) PARSE logger, like bgpipe's default --events PARSE
	p.Options.OnEvent(func(ev *Event) bool {
		time.Sleep(time.Millisecond)
		return true
	}, EVENT_PARSE)

	var established atomic.Int32
	p.Options.OnEstablished(func(ev *Event) bool {
		established.Add(1)
		return true
	})

	// a regular callback that needs parsed UPDATEs
	var seen atomic.Int64
	p.Options.OnMsg(func(m *msg.Msg) bool { seen.Add(1); return true }, meta.DIR_L, msg.UPDATE)

	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	go drainLine(p.L)
	go drainLine(p.R)

	// peer (R->L, ie. into p.L) sends OPEN + KEEPALIVE + a burst of malformed UPDATEs
	go func() {
		p.L.WriteMsg(regressOpen(1))
		p.L.WriteMsg(newKeepalive())
		for range 1000 {
			if p.L.WriteMsg(regressBadUpdate()) != nil {
				return
			}
		}
	}()
	time.Sleep(50 * time.Millisecond)

	// our side replies with OPEN + KEEPALIVE
	p.R.WriteMsg(regressOpen(2))
	p.R.WriteMsg(newKeepalive())

	time.Sleep(3 * time.Second)
	t.Logf("after 3s: established=%d evch=%d/%d L.In=%d L.LastAlive=%d R.LastAlive=%d",
		established.Load(), len(p.evch), cap(p.evch), len(p.L.In), p.L.LastAlive.Load(), p.R.LastAlive.Load())
	if established.Load() == 0 && len(p.evch) == cap(p.evch) {
		t.Errorf("event system deadlocked: queue full, ESTABLISHED never delivered, inputs blocked")
	}
	p.Stop()
}

// EVENT_ESTABLISHED is emitted exactly once, although EVENT_ALIVE handlers run concurrently
func TestEstablishedOnce(t *testing.T) {
	dups := 0
	for i := 0; i < 100; i++ {
		p := newTestPipe(context.Background())
		p.Options.Caps = true
		var est atomic.Int32
		p.Options.OnEstablished(func(ev *Event) bool { est.Add(1); return true })
		if err := p.Start(); err != nil {
			t.Fatal(err)
		}
		go drainLine(p.L)
		go drainLine(p.R)
		p.L.WriteMsg(regressOpen(1))
		p.R.WriteMsg(regressOpen(2))
		time.Sleep(2 * time.Millisecond)
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); p.L.WriteMsg(newKeepalive()) }()
		go func() { defer wg.Done(); p.R.WriteMsg(newKeepalive()) }()
		wg.Wait()
		time.Sleep(20 * time.Millisecond)
		if est.Load() > 1 {
			dups++
		}
		p.Stop()
	}
	if dups > 0 {
		t.Errorf("EVENT_ESTABLISHED emitted more than once in %d/100 sessions", dups)
	}
}

// concurrent readers never see p.Caps without AS4 while it is being negotiated
func TestCapsNeverEmpty(t *testing.T) {
	var gaps int
	for i := 0; i < 100; i++ {
		p := newTestPipe(context.Background())
		p.Options.Caps = true
		p.Caps.Use(caps.CAP_AS4)
		if err := p.Start(); err != nil {
			t.Fatal(err)
		}
		go drainLine(p.L)
		go drainLine(p.R)
		var stop atomic.Bool
		var miss atomic.Int32
		go func() {
			for !stop.Load() {
				if p.Caps.Get(caps.CAP_AS4) == nil {
					miss.Add(1)
				}
			}
		}()
		p.L.WriteMsg(regressOpen(1))
		p.R.WriteMsg(regressOpen(2))
		time.Sleep(2 * time.Millisecond)
		p.L.WriteMsg(newKeepalive())
		p.R.WriteMsg(newKeepalive())
		time.Sleep(10 * time.Millisecond)
		stop.Store(true)
		if miss.Load() > 0 {
			gaps++
		}
		p.Stop()
	}
	if gaps > 0 {
		t.Errorf("concurrent reader saw p.Caps without AS4 during negotiation in %d/100 sessions", gaps)
	}
}

// pseudo-capabilities survive the negotiation
func TestCapsKeepPseudo(t *testing.T) {
	p := newTestPipe(context.Background())
	p.Options.Caps = true
	p.Caps.Use(caps.CAP_ADDPATH_GUESS)
	est := make(chan struct{})
	p.Options.OnEstablished(func(ev *Event) bool { close(est); return false })
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	go drainLine(p.L)
	go drainLine(p.R)
	p.L.WriteMsg(regressOpen(1))
	p.R.WriteMsg(regressOpen(2))
	p.L.WriteMsg(newKeepalive())
	p.R.WriteMsg(newKeepalive())
	select {
	case <-est:
	case <-time.After(3 * time.Second):
		t.Fatal("not established")
	}
	if !p.Caps.Has(caps.CAP_ADDPATH_GUESS) {
		t.Errorf("CAP_ADDPATH_GUESS dropped: %s", p.Caps.String())
	}
	p.Stop()
}

// UPDATEs parsed concurrently with the negotiation use valid caps
func TestCapsNegotiationParse(t *testing.T) {
	ka := append(append([]byte{}, msg.BgpMarker...), 0, 19, 4)
	ats := []byte{0x40, 1, 1, 0, 0x40, 2, 6, 2, 1, 0xfa, 0x56, 0xea, 0x01, 0x40, 3, 4, 10, 0, 0, 1}
	body := append([]byte{0, 0, 0, byte(len(ats))}, ats...)
	body = append(body, 24, 192, 0, 2)
	upd := append(append([]byte{}, msg.BgpMarker...), 0, byte(19+len(body)), 2)
	upd = append(upd, body...)
	var burst []byte
	for range 2000 {
		burst = append(burst, upd...)
	}

	bad := 0
	for i := 0; i < 200 && bad == 0; i++ {
		p := newTestPipe(context.Background())
		p.Options.Caps = true
		p.Caps.Use(caps.CAP_AS4) // bgpipe default (--as4 auto adds AS4 + AS_GUESS)
		var wrong atomic.Int32
		var sample atomic.Value
		p.Options.OnParseError(func(ev *Event) bool { wrong.Add(1); sample.Store("PARSE ERROR: " + ev.Error.Error()); return true })
		p.Options.OnMsg(func(m *msg.Msg) bool {
			if s := m.Update.AsPath().String(); s != "[4200000001]" {
				wrong.Add(1)
				sample.Store(s)
			}
			return true
		}, meta.DIR_R, msg.UPDATE)
		if err := p.Start(); err != nil {
			t.Fatal(err)
		}
		go drainLine(p.L)
		go drainLine(p.R)

		p.R.Write(regressOpenRaw(t, 1))
		p.L.Write(regressOpenRaw(t, 2))
		time.Sleep(time.Millisecond)
		p.R.Write(ka) // R keepalive first: R does not wait for checkEstablished
		go p.R.Write(burst)
		p.L.Write(ka) // L keepalive second: triggers checkEstablished
		time.Sleep(30 * time.Millisecond)
		if wrong.Load() > 0 {
			bad++
			t.Errorf("session %d: %d UPDATEs mis-parsed during negotiation, eg. AS_PATH=%v", i, wrong.Load(), sample.Load())
		}
		p.Stop()
	}
}

func regressOpenRaw(t *testing.T, asn uint32) []byte {
	m := regressOpen(asn)
	if err := m.Marshal(caps.Caps{}); err != nil {
		t.Fatal(err)
	}
	b := append([]byte{}, msg.BgpMarker...)
	b = append(b, byte(m.Len()>>8), byte(m.Len()), byte(m.Type))
	return append(b, m.Data...)
}

// callback tag filters see the tags set by earlier callbacks
func TestTagFilterSeesCallbackTags(t *testing.T) {
	p := newTestPipe(context.Background())
	p.Options.OnMsg(func(m *msg.Msg) bool {
		(&m.Tags).Set("x", "1")
		return true
	}, meta.DIR_R)
	f, err := filter.NewFilter(`tag[x] == 1`)
	if err != nil {
		t.Fatal(err)
	}
	var hit atomic.Int32
	cb := p.Options.OnMsg(func(m *msg.Msg) bool { hit.Add(1); return true }, meta.DIR_R)
	cb.Filter = []*filter.Filter{f}
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	out := make(chan *msg.Msg, 10)
	go func() {
		for m := range p.R.Out {
			out <- m
		}
	}()
	go drainLine(p.L)
	p.R.WriteMsg(newKeepalive())
	m := <-out
	t.Logf("tags on output: %v, filtered callback hits: %d", m.Tags, hit.Load())
	if hit.Load() == 0 && m.Tags.Get("x") == "1" {
		t.Errorf("tag set by earlier callback not visible to later callback's tag filter")
	}
	p.Stop()
}
