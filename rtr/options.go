package rtr

import (
	"net/netip"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// DefaultOptions are the default RTR client options.
var DefaultOptions = Options{
	Logger:  &log.Logger,
	Version: VersionAuto,
}

// Options configures the RTR client behavior and callbacks.
// All callbacks are called serially from the Run goroutine.
type Options struct {
	Logger  *zerolog.Logger // if nil, logging is disabled
	Version byte            // preferred RTR protocol version (VersionAuto = negotiate v2 → v1 → v0)

	// OnROA is called for each ROA announcement or withdrawal.
	// add=true means announcement; false means withdrawal.
	OnROA func(add bool, prefix netip.Prefix, maxLen uint8, asn uint32)

	// OnASPA is called for each ASPA announcement or withdrawal (RTR v2 only).
	// For withdrawals, providers is nil.
	OnASPA func(add bool, cas uint32, providers []uint32)

	// OnEndOfData is called after each complete batch of PDUs.
	// sessid and serial reflect the server's current cache state.
	OnEndOfData func(sessid uint16, serial uint32)

	// OnCacheReset is called when the server requests a full cache reload.
	// The client sends a new Reset Query automatically after this callback.
	OnCacheReset func()

	// OnError is called when the server sends an Error Report PDU.
	// code is one of the Err* constants; text may be empty.
	OnError func(code uint16, text string)
}
