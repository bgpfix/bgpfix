package pipe

import "errors"

var (
	ErrInClosed = errors.New("input channel closed")
)
