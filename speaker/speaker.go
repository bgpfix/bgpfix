// Package speaker provides a very basic BGP speaker.
package speaker

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/bgpfix/bgpfix/af"
	"github.com/bgpfix/bgpfix/caps"
	"github.com/bgpfix/bgpfix/msg"
	"github.com/bgpfix/bgpfix/pipe"
	"github.com/rs/zerolog"
)

// Speaker represents a basic BGP speaker for single-threaded use
type Speaker struct {
	*zerolog.Logger

	ctx    context.Context
	cancel context.CancelCauseFunc

	pipe *pipe.Pipe  // attached BGP pipe
	in   *pipe.Input // input for our messages
	up   *pipe.Line  // TX line
	down *pipe.Line  // RX line

	Options Options     // options; do not modify after Attach()
	opened  atomic.Bool // true iff OPEN already sent
}

// NewSpeaker returns a new Speaker. Call Speaker.Attach() next.
func NewSpeaker(ctx context.Context) *Speaker {
	s := &Speaker{}
	s.ctx, s.cancel = context.WithCancelCause(ctx)
	s.Options = DefaultOptions
	return s
}

// Attach attaches the speaker to given pipe input.
// Must not be called more than once.
func (s *Speaker) Attach(p *pipe.Pipe, dst msg.Dst) error {
	s.pipe = p
	s.in = p.AddInput(dst)
	s.up = p.LineTo(dst)
	s.down = p.LineFrom(dst)

	// process options
	opts := &s.Options
	if opts.Logger != nil {
		s.Logger = opts.Logger
	} else {
		l := zerolog.Nop()
		s.Logger = &l
	}

	// attach
	po := &s.pipe.Options
	po.OnStart(s.onStart)                    // when the pipe starts
	po.OnEstablished(s.onEstablished)        // when session is established
	po.OnMsg(s.onOpen, s.down.Dst, msg.OPEN) // on OPEN for us

	return nil
}

// onStart sends our OPEN message, if the speaker is not passive.
func (s *Speaker) onStart(_ *pipe.Event) bool {
	if !s.Options.Passive {
		s.sendOpen(nil)
	}
	return false // unregister
}

func (s *Speaker) onEstablished(ev *pipe.Event) bool {
	// load last OPENs
	up, down := s.up.Open.Load(), s.down.Open.Load()
	if up == nil || down == nil {
		return true // huh?
	}

	// start keepaliver with common hold time
	ht := min(up.HoldTime, down.HoldTime)
	if ht > 0 {
		go s.keepaliver(int64(ht))
	}

	return false // unregister
}

func (s *Speaker) onOpen(m *msg.Msg) pipe.Action {
	// TODO: validate received OPEN - drop if wrong caps / other params

	// send our OPEN (nop if we did that already)
	s.sendOpen(&m.Open)

	// confirm the received OPEN is OK
	s.sendKeepalive()

	return 0
}

func (s *Speaker) sendOpen(ro *msg.Open) {
	if s.opened.Swap(true) {
		return // already done
	}

	// local and remote OPENs
	o := &s.pipe.Get().Up(msg.OPEN).Open // our OPEN
	if ro == nil {
		ro = s.down.Open.Load()
	}

	// set caps from pipe and local options
	opts := &s.Options
	o.Caps.SetFrom(s.pipe.Caps)
	o.Caps.SetFrom(opts.LocalCaps)

	o.Identifier = opts.LocalId
	if !o.Identifier.IsValid() && ro != nil {
		o.Identifier = ro.Identifier.Prev()
	}

	if opts.LocalASN >= 0 {
		o.SetASN(opts.LocalASN) // will add AS4
	} else if opts.LocalASN < 0 && ro != nil {
		o.SetASN(ro.GetASN())
	} else {
		o.SetASN(0)
	}

	if opts.LocalHoldTime >= 0 {
		o.HoldTime = uint16(opts.LocalHoldTime)
	} else {
		o.HoldTime = msg.OPEN_HOLDTIME
	}
	if o.HoldTime > 0 && o.HoldTime < 3 {
		o.HoldTime = 3 // correct
	}

	// FIXME: add real capabilities
	o.Caps.Use(caps.CAP_EXTENDED_MESSAGE)
	o.Caps.Use(caps.CAP_ROUTE_REFRESH)
	if mp, ok := o.Caps.Use(caps.CAP_MP).(*caps.MP); ok {
		mp.Add(af.AFI_IPV4, af.SAFI_UNICAST)
		mp.Add(af.AFI_IPV4, af.SAFI_FLOWSPEC)

		mp.Add(af.AFI_IPV6, af.SAFI_UNICAST)
		mp.Add(af.AFI_IPV6, af.SAFI_FLOWSPEC)
	}

	// queue for sending
	s.in.WriteMsg(o.Msg)
}

func (s *Speaker) sendKeepalive() {
	m := s.pipe.Get().Up(msg.KEEPALIVE)
	s.in.WriteMsg(m)
}

// keepaliver sends a KEEPALIVE message, and keeps sending them to respect the hold time.
func (s *Speaker) keepaliver(negotiated int64) {
	var (
		ticker    = time.NewTicker(time.Second)
		now_ts    int64 // UNIX timestamp now
		last_up   int64 // UNIX timestamp when we last sent something to peer
		last_down int64 // UNIX timestamp when we last received something from peer
	)

	if negotiated < 3 {
		negotiated = 3
	}

	for {
		// wait 1s
		select {
		case <-s.ctx.Done():
			ticker.Stop()
			return
		case now := <-ticker.C:
			now_ts = now.Unix()
		}

		// remote timeout?
		last_down = max(s.down.LastAlive.Load(), s.down.LastUpdate.Load(), last_down)
		if delay := now_ts - last_down; delay > negotiated {
			last_down = now_ts
			s.Warn().Msg("remote hold timer expired")
			s.pipe.Event(EVENT_PEER_TIMEOUT, delay)
		}

		// local timeout?
		last_up = max(s.up.LastAlive.Load(), s.up.LastUpdate.Load(), last_up)
		if delay := now_ts - last_up; delay >= negotiated/3 {
			last_up = now_ts
			s.sendKeepalive()
		}
	}
}
