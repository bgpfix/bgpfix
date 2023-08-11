package speaker

import "github.com/bgpfix/bgpfix/pipe"

var (
	EVENT_INIT = &pipe.EventType{
		Name:  "speaker/INIT",
		Descr: "entered initial state",
	}
	EVENT_ESTABLISHED = &pipe.EventType{
		Name:  "speaker/ESTABLISHED",
		Descr: "session established",
	}
	EVENT_TOO_LONG = &pipe.EventType{
		Name:  "speaker/TOO_LONG",
		Descr: "seen a message that is too long",
	}
	EVENT_PARSE_ERROR = &pipe.EventType{
		Name:  "speaker/PARSE_ERROR",
		Descr: "message parse error",
		Value: "error message",
	}
	EVENT_RX_TIMEOUT = &pipe.EventType{
		Name:  "speaker/RX_TIMEOUT",
		Descr: "remote hold timer expired",
		Value: "nanoseconds till last RX message",
	}
)
