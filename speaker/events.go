package speaker

var (
	// seen a message that is too long
	EVENT_TOO_LONG = "bgpfix/speaker.TOO_LONG"

	// message parse error
	EVENT_PARSE_ERROR = "bgpfix/speaker.PARSE_ERROR"

	// remote hold timer expired
	// val[0] = nanoseconds till last R message
	EVENT_PEER_TIMEOUT = "bgpfix/speaker.PEER_TIMEOUT"
)
