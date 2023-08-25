package caps

import "errors"

var (
	ErrValue    = errors.New("invalid value")
	ErrLength   = errors.New("invalid length")
	ErrTODO     = errors.New("not implemented")
	ErrCapCode  = errors.New("invalid capability code")
	ErrCapValue = errors.New("invalid capability value")
)
