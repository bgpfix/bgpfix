// Package bmp supports BGP Monitoring Protocol (RFC 7854)
package bmp

import "errors"

var (
	ErrShort   = errors.New("message too short")
	ErrLength  = errors.New("invalid length")
	ErrVersion = errors.New("invalid BMP version")
)
