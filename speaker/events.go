package speaker

import "errors"

var (
	ErrRemoteASN = errors.New("remote ASN mismatch")
	ErrHoldTime  = errors.New("remote hold time rejected")
)
