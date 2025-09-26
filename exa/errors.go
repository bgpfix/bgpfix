package exa

import "errors"

var (
	// parsing errors
	ErrEmptyLine        = errors.New("empty command")
	ErrInvalidFormat    = errors.New("invalid route command format")
	ErrInvalidAction    = errors.New("command must start with announce or withdraw")
	ErrOnlyRoute        = errors.New("only route commands supported")
	ErrMissingValue     = errors.New("parameter requires value")
	ErrInvalidPrefix    = errors.New("invalid prefix format")
	ErrInvalidNextHop   = errors.New("invalid next-hop IP address")
	ErrInvalidOrigin    = errors.New("invalid origin")
	ErrInvalidCommunity = errors.New("invalid community format")

	// conversion errors
	ErrNilMessage  = errors.New("nil message")
	ErrNilLine     = errors.New("nil Exa")
	ErrNotUpdate   = errors.New("not an UPDATE message")
	ErrNextHopSelf = errors.New("next-hop 'self' must be resolved to actual IP before conversion")
	ErrNoPrefix    = errors.New("no reachable or unreachable prefixes found")

	// JSON errors
	ErrParseJSON  = errors.New("parse message JSON")
	ErrParseData  = errors.New("parse message data")
	ErrMarshalMsg = errors.New("marshal message")
)
