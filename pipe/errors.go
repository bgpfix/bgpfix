package pipe

import "errors"

var (
	ErrInClosed  = errors.New("input channel closed")
	ErrOutClosed = errors.New("output channel closed")
	ErrStopped   = errors.New("pipe stopped")
)
