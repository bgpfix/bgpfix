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
	cancel context.CancelFunc

	pipe *pipe.Pipe // attached BGP pipe

	Options   Options     // options; do not modify after Attach()
	erraction pipe.Action // action to return on error

	state State        // speaker state
	lastr atomic.Int64 // last received UPDATE or KA
	lastt atomic.Int64 // last sent UPDATE or KA
}

// State tracks where in a BGP session we are
type State int

const (
	STATE_INVALID State = iota // by default, we're nowhere; ignore everything

	STATE_INIT        // initialization
	STATE_ESTABLISHED // both OPENs sent and received, all good
)

// NewSpeaker returns a new Speaker. Call Speaker.Attach() next.
func NewSpeaker(ctx context.Context) *Speaker {
	s := &Speaker{}
	s.ctx, s.cancel = context.WithCancel(ctx)
	s.Options = DefaultOptions
	return s
}

// Attach attaches the speaker to given pipe.
// Must not be called more than once.
// TODO: support more than 1/1 t/r handlers in pipe
func (s *Speaker) Attach(p *pipe.Pipe) error {
	opts := &s.Options
	s.Logger = opts.Logger

	if opts.ErrorDrop {
		s.erraction = pipe.ACTION_DROP
	}

	// disabled? nothing to do
	if opts.Mode == SPEAKER_DISABLED {
		s.Info().Msg("speaker disabled")
		return nil
	}

	// can proceed?
	if p.Started() {
		return ErrStarted
	} else if s.pipe != nil {
		return ErrAttached
	}

	// take it and attach callbacks
	s.pipe = p
	p.Options.OnStart(s.onStart)
	p.Options.OnOpen(s.onOpen)
	p.Options.OnMsg(s.onR, msg.DST_R).Raw = true
	p.Options.OnMsg(s.onT, msg.DST_L).Raw = true

	return nil
}

func (s *Speaker) onStart(ev *pipe.Event) bool {
	opts := &s.Options

	s.state = STATE_INIT
	s.pipe.Event(EVENT_INIT, nil)

	if opts.Mode == SPEAKER_FULL && !opts.Passive {
		s.sendOpen(nil)
	}

	return false // no way back
}

func (s *Speaker) onOpen(ev *pipe.Event) bool {
	opts := &s.Options

	// TODO: validate opts.Remote*, teardown if invalid

	// TODO: announce ESTABLISHED only after the first KEEPALIVE is received
	s.state = STATE_ESTABLISHED
	s.pipe.Event(EVENT_ESTABLISHED, nil)

	if opts.Mode == SPEAKER_FULL {
		ht := min(s.pipe.R.Open.Load().HoldTime, s.pipe.L.Open.Load().HoldTime)
		go s.keepaliver(ht)
	}

	return false // no way back
}

// sendOpen generates a new OPEN and writes it to p.L
func (s *Speaker) sendOpen(ro *msg.Open) {
	opts := &s.Options
	p := s.pipe

	o := &p.Get(msg.OPEN).Open
	o.Identifier = opts.LocalId

	if opts.LocalASN > 0 {
		o.SetASN(opts.LocalASN) // will add AS4
	} else if opts.LocalASN < 0 && ro != nil {
		o.SetASN(ro.GetASN())
	}

	if opts.LocalHoldTime >= 0 {
		o.HoldTime = uint16(opts.LocalHoldTime)
	} else {
		o.HoldTime = msg.OPEN_HOLDTIME
	}
	if o.HoldTime > 0 && o.HoldTime < 3 {
		o.HoldTime = 3 // correct
	}

	if !o.Identifier.IsValid() && ro != nil {
		o.Identifier = ro.Identifier.Prev()
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
	o.Caps.SetFrom(p.Caps)
	o.Caps.SetFrom(opts.LocalCaps)

	// queue for L
	p.L.In <- o.Msg
}

// keepaliver sends a KEEPALIVE message, and keeps sending them to respect the hold time.
// it is run only in full speaker mode.
func (s *Speaker) keepaliver(negotiated uint16) {
	// send the first KA to confirm the pipe is established
	p := s.pipe
	p.L.In <- p.Get(msg.KEEPALIVE)

	// check the hold time
	if negotiated == 0 {
		return // done
	} else if negotiated < 3 {
		negotiated = 3
	}

	// keep checking every second
	ticker := time.NewTicker(time.Second)

	// send KEEPALIVE 1s before each ~1/3 of the negotiated hold timer
	second := int64(time.Second)
	hold := second * int64(negotiated)
	each := hold/3 - second
	for range ticker.C {
		// we're done?
		if s.ctx.Err() != nil {
			return
		}

		// get data
		now := nanotime()
		lr := s.lastr.Load()
		lt := s.lastt.Load()

		// timeout?
		if now-lr > hold {
			s.Warn().Msg("remote hold timer expired")
			p.Event(EVENT_R_TIMEOUT, nil, now-lr)
		}

		// need to send our next KA?
		if now-lt >= each {
			p.L.In <- p.Get(msg.KEEPALIVE)
		}
	}
}

func (s *Speaker) onR(m *msg.Msg) pipe.Action {
	opts := &s.Options
	p := s.pipe

	// check if m too long vs. extmsg?
	if m.Length() > msg.MAXLEN && !p.Caps.Has(caps.CAP_EXTENDED_MESSAGE) {
		p.Event(EVENT_TOO_LONG, m)
		// TODO: notify + teardown
		return s.erraction
	}

	// try to parse
	// FIXME: MODE_INFER
	if err := m.ParseUpper(p.Caps); err != nil {
		p.Event(EVENT_PARSE_ERROR, m, err.Error())
		// TODO: notify + teardown?
		return s.erraction
	}

	switch m.Type {
	case msg.OPEN:
		// TODO: drop if in state established and seen an update?
		// TODO: drop if wrong caps / other params?
		if opts.Mode == SPEAKER_FULL && opts.Passive {
			s.sendOpen(&m.Open)
		}

	case msg.UPDATE, msg.KEEPALIVE:
		s.lastr.Store(nanotime())

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

func (s *Speaker) onT(m *msg.Msg) pipe.Action {
	opts := &s.Options
	p := s.pipe

	// check if m too long vs. extmsg
	if m.Length() > msg.MAXLEN && !p.Caps.Has(caps.CAP_EXTENDED_MESSAGE) {
		p.Event(EVENT_TOO_LONG, m)
		return s.erraction
	}

	// try to parse
	// FIXME: MODE_INFER
	if err := m.ParseUpper(p.Caps); err != nil {
		p.Event(EVENT_PARSE_ERROR, m, err)
		// TODO: notify + teardown?
		return s.erraction
	}

	switch m.Type {
	case msg.OPEN:
		break // OK

	case msg.UPDATE, msg.KEEPALIVE:
		s.lastt.Store(nanotime())

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
