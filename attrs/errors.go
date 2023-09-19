package attrs

import "errors"

var (
	ErrTODO   = errors.New("not implemented")
	ErrValue  = errors.New("invalid value")
	ErrLength = errors.New("invalid length")

	ErrAF          = errors.New("invalid IP version")
	ErrAttrCode    = errors.New("invalid attribute code")
	ErrAttrFlags   = errors.New("invalid attribute flags")
	ErrAttrValue   = errors.New("invalid attribute value")
	ErrSegType     = errors.New("invalid ASPATH segment type")
	ErrSegLen      = errors.New("invalid ASPATH segment length")
	ErrFlowType    = errors.New("invalid Flowspec component type")
	ErrFlowValue   = errors.New("invalid Flowspec component value")
	ErrExtcomType  = errors.New("invalid extended community type")
	ErrExtcomValue = errors.New("invalid extended community value")
)
