package speaker

import "errors"

var (
	ErrStarted  = errors.New("session already started")
	ErrAttached = errors.New("speaker already attached")
)
