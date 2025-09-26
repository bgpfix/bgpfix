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
)
