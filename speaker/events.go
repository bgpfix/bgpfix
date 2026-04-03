package speaker

import "errors"

var (
	// remote hold timer expired
	EVENT_PEER_TIMEOUT = "bgpfix/speaker.PEER_TIMEOUT"
)

var (
	ErrRemoteASN = errors.New("remote ASN mismatch")
	ErrHoldTime  = errors.New("remote hold time rejected")
)
