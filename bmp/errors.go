// Package bmp supports BGP Monitoring Protocol (RFC 7854)
package bmp

import "errors"

var (
	ErrShort   = errors.New("message too short")
	ErrLength  = errors.New("invalid length")
	ErrVersion = errors.New("invalid BMP version")
	ErrType    = errors.New("invalid BMP message type")
	ErrNoData  = errors.New("no message data")
)
