package speaker

import (
	"net/netip"

	"github.com/bgpfix/bgpfix/caps"
	"github.com/bgpfix/bgpfix/msg"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// Default BGP speaker options
var DefaultOptions = Options{
	Logger:        log.Logger,
	Mode:          SPEAKER_FULL,
	Passive:       true,
	LocalASN:      -1,
	LocalHoldTime: msg.OPEN_HOLDTIME,
	RemoteASN:     -1,
}

// Options are BGP speaker options, see also DefaultOptions
type Options struct {
	Logger zerolog.Logger // use zerolog.Nop to disable logging

	Mode      Mode // zero means don't do anything
	Passive   bool // if true, expect the peer to go first with OPEN
	ErrorDrop bool // drop erronous messages?

	LocalASN      int        // local ASN; -1 means use remote (if Passive)
	LocalHoldTime int        // local hold time (s); -1 means use a default
	LocalId       netip.Addr // local identifier; unspecified means use remote-1 (if Passive)
	LocalCaps     caps.Caps  // additional local capabilities; set to nil to block a capability

	RemoteASN      int        // expected remote ASN; -1 means accept any
	RemoteHoldTime int        // minimum remote hold time (s); <= 0 means any
	RemoteId       netip.Addr // expected remote identifier; unspecified means any
	RemoteCaps     caps.Caps  // minimum remote capabilities; set to nil to block a capability
}

// Mode controls how much we should engage in the attached BGP processor
type Mode int

const (
	SPEAKER_DISABLED Mode = iota // don't do anything

	SPEAKER_READONLY // readonly, just listen to open / keepalive / notify
	SPEAKER_INFER    // as READONLY + try to infer capabilities from update messages
	SPEAKER_FULL     // receive and transmit BGP messages
)
