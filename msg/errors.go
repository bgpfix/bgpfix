package msg

import "errors"

var (
	// generic errors
	ErrTODO        = errors.New("not implemented")
	ErrUnsupported = errors.New("unsupported")
	ErrType        = errors.New("invalid type")
	ErrValue       = errors.New("invalid value")
	ErrLength      = errors.New("invalid length")
	ErrShort       = errors.New("too short")
	ErrLong        = errors.New("too long")

	ErrMarker    = errors.New("marker not found")
	ErrVersion   = errors.New("invalid version")
	ErrParams    = errors.New("invalid parameters")
	ErrCaps      = errors.New("invalid capabilities")
	ErrAttrDupe  = errors.New("duplicate attribute")
	ErrAttrCode  = errors.New("invalid attribute code")
	ErrAttrFlags = errors.New("invalid attribute flags")
	ErrAttrs     = errors.New("invalid attributes")
	ErrSegType   = errors.New("invalid segment type")
	ErrSegLen    = errors.New("invalid segment length")
)
