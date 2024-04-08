package mrt

import "errors"

var (
	ErrShort  = errors.New("message too short")
	ErrLong   = errors.New("message too long")
	ErrLength = errors.New("invalid length")
	ErrType   = errors.New("invalid MRT type")
	ErrSub    = errors.New("invalid MRT subtype")
	ErrAF     = errors.New("invalid Address Family")
	ErrNoData = errors.New("no message data")
)
