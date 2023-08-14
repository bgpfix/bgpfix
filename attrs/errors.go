package attrs

import "errors"

var (
	ErrTODO   = errors.New("not implemented")
	ErrValue  = errors.New("invalid value")
	ErrLength = errors.New("invalid length")

	ErrAttrCode  = errors.New("invalid attribute code")
	ErrAttrFlags = errors.New("invalid attribute flags")
	ErrSegType   = errors.New("invalid segment type")
	ErrSegLen    = errors.New("invalid segment length")
)
