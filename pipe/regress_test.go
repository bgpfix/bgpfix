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

// Stop() before Start(): Start returns ErrStopped without wgstart.Done(), so Wait() hangs forever.
// bgpipe calls Pipe.Start() (ignoring the error) and then Pipe.Wait().
func TestRegress_StopBeforeStartWaitHangs(t *testing.T) {
	p := newTestPipe(context.Background())
	p.Stop()
	err := p.Start()
	t.Logf("Start() after Stop() = %v", err)
	if !doneWithin(p.Wait, 2*time.Second) {
		t.Errorf("BUG: Pipe.Wait() hangs forever after Stop() raced ahead of Start()")
	}
}

// Concurrent Start()/Stop(): Stop sees started=true and blocks on wgstart, while Start sees
// stopped=true and returns ErrStopped without wgstart.Done() -> Stop() hangs forever.
func TestRegress_StartStopRaceHangs(t *testing.T) {
	hangs := 0
	for i := 0; i < 2000 && hangs == 0; i++ {
		p := newTestPipe(context.Background())
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); p.Start() }()
		go func() { defer wg.Done(); p.Stop() }()
		if !doneWithin(wg.Wait, 2*time.Second) {
			hangs++
			t.Errorf("BUG: iteration %d: concurrent Start()/Stop() deadlocked", i)
		} else {
			go drainLine(p.L)
			go drainLine(p.R)
			p.Stop()
		}
	}
}

// A Handler calling Pipe.Stop() deadlocks forever: Stop() waits for evwg, which includes itself.
func TestRegress_StopFromHandlerDeadlocks(t *testing.T) {
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
		t.Errorf("BUG: Pipe.Stop() called from an event handler never returns; Pipe.Wait() hangs forever")
	}
}

// The event queue (100) fills up with EVENT_PARSE from a peer sending malformed UPDATEs.
// With GOMAXPROCS=1 there is a single event goroutine; the internal checkEstablished handler
// calls p.Event(EVENT_ESTABLISHED), which blocks on the full queue -> the event system and
// every input that emits an event are deadlocked until Stop()/cancel. Nothing ever times out.
func TestRegress_EventQueueDeadlock(t *testing.T) {
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
		t.Errorf("BUG: event system deadlocked: queue full, ESTABLISHED never delivered, inputs blocked")
	}
	p.Stop()
}

// The EVENT_ALIVE handler (checkEstablished) can run concurrently on two event goroutines:
// EVENT_ESTABLISHED is emitted twice, and p.Caps is Clear()ed/SetFrom()'ed concurrently.
func TestRegress_DuplicateEstablished(t *testing.T) {
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
		t.Errorf("BUG: EVENT_ESTABLISHED emitted more than once in %d/100 sessions", dups)
	}
}

// checkEstablished does p.Caps.Clear() then p.Caps.SetFrom(): a concurrent UPDATE parser in the
// direction that is not waiting for ev.done observes an empty Caps (no AS4 => 2-byte AS_PATH decode).
func TestRegress_CapsTransientlyEmpty(t *testing.T) {
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
		t.Errorf("BUG: concurrent reader saw p.Caps without AS4 during negotiation in %d/100 sessions", gaps)
	}
}

// Same as above, but shows real UPDATE mis-parsing in the non-waiting direction.
func TestRegress_CapsRaceMisparse(t *testing.T) {
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
			t.Errorf("BUG: session %d: %d UPDATEs mis-parsed during negotiation, eg. AS_PATH=%v", i, wrong.Load(), sample.Load())
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

// eval.Set() snapshots mx.tags once per message, before callbacks. If the message had no tags
// map yet (any freshly allocated msg), a tag set by an earlier callback (eg. bgpipe "tag" stage)
// is invisible to the --if filters of all later callbacks.
func TestRegress_TagFilterStaleSnapshot(t *testing.T) {
	p := newTestPipe(context.Background())
	p.Options.OnMsg(func(m *msg.Msg) bool {
		UseContext(m).SetTag("x", "1")
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
	t.Logf("tags on output: %v, filtered callback hits: %d", GetTags(m), hit.Load())
	if hit.Load() == 0 && GetTags(m)["x"] == "1" {
		t.Errorf("BUG: tag set by earlier callback not visible to later callback's tag filter")
	}
	p.Stop()
}
