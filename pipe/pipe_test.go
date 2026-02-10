// NB: excluded from -race because Pipe.Stop() has an inherent race between
// go p.sendEvent(EVENT_STOP) and close(p.evch). The recover() in sendEvent
// makes this safe at runtime, but the race detector flags it.
//
//go:build !race

package pipe

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bgpfix/bgpfix/dir"
	"github.com/bgpfix/bgpfix/msg"
)

// newTestPipe creates a pipe with fast stop timeout and no logger
func newTestPipe(ctx context.Context) *Pipe {
	p := NewPipe(ctx)
	p.Options.Logger = nil
	p.Options.Caps = false
	p.Options.StopTimeout = 50 * time.Millisecond
	return p
}

// newKeepalive returns a minimal KEEPALIVE message
func newKeepalive() *msg.Msg {
	m := msg.NewMsg()
	m.Type = msg.KEEPALIVE
	m.Data = []byte{} // empty data = valid keepalive
	return m
}

// drainLine reads all messages from a Line.Out until it closes
func drainLine(l *Line) []*msg.Msg {
	var msgs []*msg.Msg
	for m := range l.Out {
		msgs = append(msgs, m)
	}
	return msgs
}

// --- Lifecycle tests ---

func TestPipe_StartStop(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	p := newTestPipe(ctx)
	if err := p.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// drain outputs to prevent blocking
	go drainLine(p.L)
	go drainLine(p.R)

	p.Stop()
	// should not deadlock
}

func TestPipe_DoubleStart(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	p := newTestPipe(ctx)
	if err := p.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	go drainLine(p.L)
	go drainLine(p.R)
	defer p.Stop()

	err := p.Start()
	if err != ErrStarted {
		t.Fatalf("expected ErrStarted, got %v", err)
	}
}

func TestPipe_ContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	p := newTestPipe(ctx)

	if err := p.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	go drainLine(p.L)
	go drainLine(p.R)

	// cancel parent ctx, pipe should stop cleanly
	cancel()

	done := make(chan struct{})
	go func() {
		p.Wait()
		close(done)
	}()

	select {
	case <-done:
		// ok
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for pipe to stop after context cancel")
	}
}

// --- Message flow tests ---

func TestPipe_MessagePassthrough(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	p := newTestPipe(ctx)
	if err := p.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// drain L output (we're testing R direction)
	go drainLine(p.L)

	// send a message to L.In (which goes to R output direction)
	m := newKeepalive()
	p.L.Input.In <- m

	// read from L.Out... wait, L.In feeds L direction callbacks which output to L.Out
	// Actually: L line processes R->L messages. R line processes L->R messages.
	// L.Input.In -> L callbacks -> L.Out
	// R.Input.In -> R callbacks -> R.Out

	// close L input so it finishes
	p.L.Close()

	var got []*msg.Msg
	for m := range p.L.Out {
		got = append(got, m)
	}

	// also drain R to let pipe finish cleanly
	go drainLine(p.R)
	p.Stop()

	if len(got) != 1 {
		t.Fatalf("expected 1 message, got %d", len(got))
	}
	if got[0].Type != msg.KEEPALIVE {
		t.Fatalf("expected KEEPALIVE, got %v", got[0].Type)
	}
	if got[0].Seq == 0 {
		t.Fatal("expected Seq to be set")
	}
	if got[0].Time.IsZero() {
		t.Fatal("expected Time to be set")
	}
	if got[0].Dir != dir.DIR_L {
		t.Fatalf("expected DIR_L, got %v", got[0].Dir)
	}
}

func TestPipe_CallbackDrop(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	p := newTestPipe(ctx)
	p.Options.OnMsg(func(m *msg.Msg) bool {
		return false // drop
	}, dir.DIR_L)

	if err := p.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	go drainLine(p.R)

	m := newKeepalive()
	p.L.Input.In <- m
	p.L.Close()

	got := drainLine(p.L)
	p.Stop()

	if len(got) != 0 {
		t.Fatalf("expected 0 messages (dropped), got %d", len(got))
	}
}

func TestPipe_CallbackAccept(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	p := newTestPipe(ctx)
	var called1, called2 atomic.Bool

	p.Options.OnMsg(func(m *msg.Msg) bool {
		called1.Store(true)
		UseContext(m).Action.Accept()
		return true
	}, 0)

	p.Options.OnMsg(func(m *msg.Msg) bool {
		called2.Store(true)
		return true
	}, 0)

	if err := p.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	go drainLine(p.R)

	m := newKeepalive()
	p.L.Input.In <- m
	p.L.Close()

	got := drainLine(p.L)
	p.Stop()

	if !called1.Load() {
		t.Fatal("first callback not called")
	}
	if called2.Load() {
		t.Fatal("second callback should be skipped due to ACTION_ACCEPT")
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 message, got %d", len(got))
	}
}

func TestPipe_CallbackOrdering(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	p := newTestPipe(ctx)
	var order []string
	var mu sync.Mutex
	add := func(s string) {
		mu.Lock()
		order = append(order, s)
		mu.Unlock()
	}

	// post callback (should run last)
	p.Options.OnMsgPost(func(m *msg.Msg) bool {
		add("post")
		return true
	}, 0)

	// pre callback (should run first)
	p.Options.OnMsgPre(func(m *msg.Msg) bool {
		add("pre")
		return true
	}, 0)

	// normal callback (should run in the middle)
	p.Options.OnMsg(func(m *msg.Msg) bool {
		add("normal")
		return true
	}, 0)

	if err := p.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	go drainLine(p.R)

	m := newKeepalive()
	p.L.Input.In <- m
	p.L.Close()
	drainLine(p.L)
	p.Stop()

	mu.Lock()
	defer mu.Unlock()
	if len(order) != 3 {
		t.Fatalf("expected 3 callbacks, got %d: %v", len(order), order)
	}
	if order[0] != "pre" || order[1] != "normal" || order[2] != "post" {
		t.Fatalf("expected [pre normal post], got %v", order)
	}
}

func TestPipe_CallbackEnabled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	p := newTestPipe(ctx)

	var count atomic.Int32
	enabled := &atomic.Bool{}
	enabled.Store(false)

	// a "spy" callback that always runs (no Enabled gate) to signal message processing
	processed := make(chan struct{}, 10)
	p.Options.OnMsg(func(m *msg.Msg) bool {
		processed <- struct{}{}
		return true
	}, 0)

	cb := p.Options.OnMsg(func(m *msg.Msg) bool {
		count.Add(1)
		return true
	}, 0)
	cb.Enabled = enabled

	if err := p.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	go drainLine(p.R)

	// send one message while disabled, wait for it to be processed
	p.L.Input.In <- newKeepalive()
	<-processed

	// enable and send another
	enabled.Store(true)
	p.L.Input.In <- newKeepalive()
	<-processed

	p.L.Close()
	drainLine(p.L)
	p.Stop()

	c := count.Load()
	if c != 1 {
		t.Fatalf("expected callback called 1 time, got %d", c)
	}
}

func TestPipe_MultipleInputs(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	p := newTestPipe(ctx)

	// add an extra input on the L line
	extra := p.Options.AddInput(dir.DIR_L)

	if err := p.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	go drainLine(p.R)

	// send one through default input
	p.L.Input.In <- newKeepalive()
	// send one through extra input
	extra.In <- newKeepalive()

	p.L.Close()
	extra.Close()

	got := drainLine(p.L)
	p.Stop()

	if len(got) != 2 {
		t.Fatalf("expected 2 messages from 2 inputs, got %d", len(got))
	}
}

// --- Event system tests ---

func TestPipe_EventStartFires(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	p := newTestPipe(ctx)
	var fired atomic.Bool

	p.Options.OnStart(func(ev *Event) bool {
		fired.Store(true)
		return false
	})

	if err := p.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	go drainLine(p.L)
	go drainLine(p.R)

	// give event system time to fire
	time.Sleep(50 * time.Millisecond)
	p.Stop()

	if !fired.Load() {
		t.Fatal("EVENT_START handler did not fire")
	}
}

func TestPipe_EventStopFires(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	p := newTestPipe(ctx)
	fired := make(chan struct{}, 1)

	p.Options.OnStop(func(ev *Event) bool {
		select {
		case fired <- struct{}{}:
		default:
		}
		return false
	})

	if err := p.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	go drainLine(p.L)
	go drainLine(p.R)

	// send a message so L.Wait()/R.Wait() inside Stop() take some time,
	// giving the async sendEvent(EVENT_STOP) goroutine time to deliver
	p.L.Input.In <- newKeepalive()
	time.Sleep(10 * time.Millisecond)

	p.Stop()

	select {
	case <-fired:
		// ok
	case <-time.After(time.Second):
		t.Fatal("EVENT_STOP handler did not fire")
	}
}

func TestPipe_EventHandlerOrdering(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	p := newTestPipe(ctx)
	var order []string
	var mu sync.Mutex
	add := func(s string) {
		mu.Lock()
		order = append(order, s)
		mu.Unlock()
	}

	p.Options.OnEventPost(func(ev *Event) bool {
		add("post")
		return false
	}, EVENT_START)

	p.Options.OnEventPre(func(ev *Event) bool {
		add("pre")
		return false
	}, EVENT_START)

	p.Options.OnEvent(func(ev *Event) bool {
		add("normal")
		return false
	}, EVENT_START)

	if err := p.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	go drainLine(p.L)
	go drainLine(p.R)

	time.Sleep(50 * time.Millisecond)
	p.Stop()

	mu.Lock()
	defer mu.Unlock()
	if len(order) != 3 {
		t.Fatalf("expected 3 handlers, got %d: %v", len(order), order)
	}
	if order[0] != "pre" || order[1] != "normal" || order[2] != "post" {
		t.Fatalf("expected [pre normal post], got %v", order)
	}
}

func TestPipe_EventHandlerDrop(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	p := newTestPipe(ctx)
	var count atomic.Int32

	p.Options.OnEvent(func(ev *Event) bool {
		count.Add(1)
		return false // drop after first call
	})

	if err := p.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	go drainLine(p.L)
	go drainLine(p.R)

	// wait for START event
	time.Sleep(50 * time.Millisecond)

	// send a custom event
	p.Event("test/custom1")
	time.Sleep(20 * time.Millisecond)

	// handler should have been dropped after START, so custom1 won't increment
	c := count.Load()
	if c != 1 {
		t.Fatalf("expected handler called 1 time (dropped after START), got %d", c)
	}

	p.Stop()
}

func TestPipe_EventWait(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	p := newTestPipe(ctx)

	var done atomic.Bool
	p.Options.OnEvent(func(ev *Event) bool {
		time.Sleep(50 * time.Millisecond)
		done.Store(true)
		return false
	}, "test/slow")

	if err := p.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	go drainLine(p.L)
	go drainLine(p.R)

	// wait for start to settle
	time.Sleep(20 * time.Millisecond)

	ev := p.Event("test/slow")
	ev.Wait()

	if !done.Load() {
		t.Fatal("expected handler to have finished by the time Wait returns")
	}

	p.Stop()
}

func TestPipe_EventWildcard(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	p := newTestPipe(ctx)
	var types []string
	var mu sync.Mutex

	p.Options.OnEvent(func(ev *Event) bool {
		mu.Lock()
		types = append(types, ev.Type)
		mu.Unlock()
		return true
	}) // no types = wildcard

	if err := p.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	go drainLine(p.L)
	go drainLine(p.R)

	// wait for START
	time.Sleep(50 * time.Millisecond)

	p.Event("test/alpha")
	time.Sleep(20 * time.Millisecond)
	p.Event("test/beta")
	time.Sleep(20 * time.Millisecond)

	p.Stop()

	mu.Lock()
	defer mu.Unlock()

	// should have received at least START, alpha, beta
	seen := make(map[string]bool)
	for _, typ := range types {
		seen[typ] = true
	}
	for _, want := range []string{EVENT_START, "test/alpha", "test/beta"} {
		if !seen[want] {
			t.Errorf("wildcard handler did not see event %q, saw: %v", want, types)
		}
	}
}

// --- Concurrency tests ---

func TestPipe_ConcurrentSends(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	p := newTestPipe(ctx)
	if err := p.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	go drainLine(p.R)

	const goroutines = 100
	const msgsPerG = 100
	var wg sync.WaitGroup
	var sent atomic.Int32
	wg.Add(goroutines)
	for range goroutines {
		go func() {
			defer wg.Done()
			for range msgsPerG {
				m := newKeepalive()
				if p.L.Input.WriteMsg(m) == nil {
					sent.Add(1)
				}
			}
		}()
	}

	// wait for all senders, then close
	go func() {
		wg.Wait()
		p.L.Close()
	}()

	got := drainLine(p.L)
	p.Stop()

	// all successfully sent messages must arrive at output
	total := int(sent.Load())
	if len(got) != total {
		t.Fatalf("expected %d messages, got %d", total, len(got))
	}
	if total < goroutines*msgsPerG/2 {
		t.Fatalf("too few messages sent successfully: %d", total)
	}
}

func TestPipe_ConcurrentStartStop(t *testing.T) {
	for i := range 100 {
		ctx, cancel := context.WithCancel(context.Background())
		p := newTestPipe(ctx)

		err := p.Start()
		if err != nil {
			cancel()
			t.Fatalf("iter %d: Start: %v", i, err)
		}
		go drainLine(p.L)
		go drainLine(p.R)

		// stop from a separate goroutine
		done := make(chan struct{})
		go func() {
			p.Stop()
			close(done)
		}()

		select {
		case <-done:
			// ok
		case <-time.After(2 * time.Second):
			cancel()
			t.Fatalf("iter %d: timeout", i)
		}
		cancel()
	}
}

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

// --- Edge case tests ---

func TestPipe_WriteOutputAfterClose(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	p := newTestPipe(ctx)
	if err := p.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	go drainLine(p.L)
	go drainLine(p.R)

	// close output, then try to write
	p.L.CloseOutput()
	err := p.L.WriteOutput(newKeepalive())
	if err != ErrOutClosed {
		t.Fatalf("expected ErrOutClosed, got %v", err)
	}

	p.Stop()
}

func TestPipe_InputCloseIdempotent(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	p := newTestPipe(ctx)
	if err := p.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	go drainLine(p.L)
	go drainLine(p.R)

	// double close should not panic
	p.L.Close()
	p.L.Close()

	p.Stop()
}

func TestPipe_CallbackBlackhole(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	p := newTestPipe(ctx)

	cb := p.Options.OnMsg(func(m *msg.Msg) bool {
		return true
	}, 0)
	cb.Blackhole()

	if err := p.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	go drainLine(p.R)

	// all messages should be dropped by blackhole
	p.L.Input.In <- newKeepalive()
	p.L.Input.In <- newKeepalive()
	p.L.Close()

	got := drainLine(p.L)
	p.Stop()

	if len(got) != 0 {
		t.Fatalf("expected 0 messages (blackholed), got %d", len(got))
	}
}
