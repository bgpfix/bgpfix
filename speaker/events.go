package speaker

import "errors"

var (
	ErrRemoteASN     = errors.New("remote ASN mismatch")
	ErrHoldTime      = errors.New("remote hold time rejected")
	ErrPeerTimeout   = errors.New("remote hold timer expired")
	ErrDuplicateOPEN = errors.New("duplicate OPEN received")
	ErrRemoteId      = errors.New("remote identifier rejected")
	ErrRemoteCaps    = errors.New("remote capabilities rejected")
	ErrOpenTimeout   = errors.New("session not established in time")
)
