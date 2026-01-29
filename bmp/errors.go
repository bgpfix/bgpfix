package bmp

import "errors"

var (
	ErrShort   = errors.New("message too short")
	ErrLength  = errors.New("invalid length")
	ErrVersion = errors.New("invalid BMP version")

	// OpenBMP errors
	ErrOpenBmpMagic    = errors.New("invalid OpenBMP magic")
	ErrOpenBmpVersion  = errors.New("unsupported OpenBMP version")
	ErrOpenBmpRowCount = errors.New("invalid OpenBMP row count")

	// Reader errors
	ErrNotRouteMonitoring = errors.New("not a Route Monitoring message")
	ErrNoBgpData          = errors.New("no BGP data in message")

	// Writer errors
	ErrNoData = errors.New("no data to write")
)
