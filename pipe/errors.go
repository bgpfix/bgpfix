package pipe

import "errors"

var (
	ErrInClosed  = errors.New("input channel closed")
	ErrOutClosed = errors.New("output channel closed")
	ErrStarted   = errors.New("pipe started")
	ErrStopped   = errors.New("pipe stopped")
	ErrFilter    = errors.New("filter error")
)
