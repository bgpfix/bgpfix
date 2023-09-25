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
	zerolog.Logger

	ctx    context.Context
	cancel context.CancelCauseFunc

	pipe *pipe.Pipe      // attached BGP pipe
	up   *pipe.Direction // upstream direction
	down *pipe.Direction // downstream direction

	Options   Options     // options; do not modify after Attach()
	erraction pipe.Action // action to return on error

	alive_down atomic.Int64 // last received UPDATE or KA
	alive_up   atomic.Int64 // last sent UPDATE or KA
}

// NewSpeaker returns a new Speaker. Call Speaker.Attach() next.
func NewSpeaker(ctx context.Context) *Speaker {
	s := &Speaker{}
	s.ctx, s.cancel = context.WithCancelCause(ctx)
	s.Options = DefaultOptions
	return s
}

// Attach attaches the speaker in given pipe direction.
// Must not be called more than once.
func (s *Speaker) Attach(upstream *pipe.Direction) error {
	opts := &s.Options
	s.Logger = opts.Logger
	s.pipe = upstream.Pipe
	s.up = upstream
	s.down = upstream.Opposite

	if opts.ErrorDrop {
		s.erraction = pipe.ACTION_DROP
	}

	po := &s.pipe.Options
	po.OnMsg(s.onMsgUp, s.up.Dst).Raw = true
	po.OnMsg(s.onMsgDown, s.down.Dst).Raw = true
	po.OnEstablished(s.onEstablished)
	if opts.OnStart {
		po.OnStart(s.OnStart)
	}

	return nil
}

// OnStart is, by default, called when the pipe starts
func (s *Speaker) OnStart(_ *pipe.Event) bool {
	if !s.Options.Passive {
		s.sendOpen(nil)
	}
	return false // unregister
}

func (s *Speaker) onEstablished(ev *pipe.Event) bool {
	// start keepaliver with common hold time
	ht := min(s.up.Open.Load().HoldTime, s.down.Open.Load().HoldTime)
	if ht > 0 {
		go s.keepaliver(ht)
	}

	return false // unregister
}

func (s *Speaker) onMsgDown(m *msg.Msg) pipe.Action {
	opts := &s.Options
	p := s.pipe

	// check if m too long vs. extmsg?
	if m.Length() > msg.MAXLEN && !p.Caps.Has(caps.CAP_EXTENDED_MESSAGE) {
		p.Event(EVENT_TOO_LONG, m)
		// TODO: notify + teardown
		return s.erraction
	}

	// try to parse
	if err := m.ParseUpper(p.Caps); err != nil {
		p.Event(EVENT_PARSE_ERROR, m, err.Error())
		// TODO: notify + teardown?
		return s.erraction
	}

	switch m.Type {
	case msg.OPEN:
		// TODO: drop if in state established and seen an update?
		// TODO: validate received OPEN - drop if wrong caps / other params?

		// send our OPEN iff we didn't do that already
		if opts.Passive {
			s.sendOpen(&m.Open)
		}

		// confirm the received OPEN is OK
		s.sendKeepalive()

	case msg.UPDATE, msg.KEEPALIVE:
		s.alive_down.Store(nanotime())

	case msg.NOTIFY:
		// TODO
	case msg.REFRESH:
		// TODO

	default:
		if opts.ErrorDrop {
			s.Error().Msgf("R: dropping invalid type %s", m.Type)
			return s.erraction
		}
	}

	return 0
}

func (s *Speaker) onMsgUp(m *msg.Msg) pipe.Action {
	opts := &s.Options
	p := s.pipe

	// check if m too long vs. extmsg
	if m.Length() > msg.MAXLEN && !p.Caps.Has(caps.CAP_EXTENDED_MESSAGE) {
		p.Event(EVENT_TOO_LONG, m)
		return s.erraction
	}

	// try to parse
	if err := m.ParseUpper(p.Caps); err != nil {
		p.Event(EVENT_PARSE_ERROR, m, err)
		// TODO: notify + teardown?
		return s.erraction
	}

	switch m.Type {
	case msg.OPEN:
		break // OK

	case msg.UPDATE, msg.KEEPALIVE:
		s.alive_up.Store(nanotime())

	case msg.NOTIFY:
		// TODO
	case msg.REFRESH:
		// TODO

	default:
		if opts.ErrorDrop {
			s.Error().Msgf("L: dropping invalid type %s", m.Type)
			return s.erraction
		}
	}

	return 0
}

// sendOpen generates a new OPEN and writes it to s.up
func (s *Speaker) sendOpen(ro *msg.Open) {
	o := &s.pipe.Get(msg.OPEN).Open // our OPEN
	if ro == nil {                  // remote OPEN
		ro = s.down.Open.Load() // in case its already available
	}

	opts := &s.Options
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

	// possibly overwrite with pipe and local capabilities
	o.Caps.SetFrom(s.pipe.Caps)
	o.Caps.SetFrom(opts.LocalCaps)

	// queue for sending
	s.up.WriteMsg(o.Msg)
}

func (s *Speaker) sendKeepalive() {
	s.up.WriteMsg(s.pipe.Get(msg.KEEPALIVE))
}

// keepaliver sends a KEEPALIVE message, and keeps sending them to respect the hold time.
func (s *Speaker) keepaliver(negotiated uint16) {
	p := s.pipe

	if negotiated < 3 {
		negotiated = 3
	}

	// keep checking every second
	// send KEEPALIVE 1s before each ~1/3 of the negotiated hold timer
	ticker := time.NewTicker(time.Second)
	second := int64(time.Second)
	hold := second * int64(negotiated)
	each := hold/3 - second
	for {
		// wait for next tick
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			// ok
		}

		// get data
		now := nanotime()
		alive_down := s.alive_down.Load()
		alive_up := s.alive_up.Load()

		// timeout?
		if now-alive_down > hold {
			s.Warn().Msg("remote hold timer expired")
			p.Event(EVENT_PEER_TIMEOUT, nil, now-alive_down)
		}

		// need to send our next KA?
		if now-alive_up >= each {
			s.sendKeepalive()
		}
	}
}
