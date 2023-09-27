package mrt

import (
	"github.com/bgpfix/bgpfix/msg"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// Default MRT-BGP reader options
var DefaultReaderOptions = ReaderOptions{
	Logger: &log.Logger,
}

// MRT-BGP Reader options
type ReaderOptions struct {
	Logger *zerolog.Logger // if nil logging is disabled
	NewMsg func() *msg.Msg // optional source of new messages
}
