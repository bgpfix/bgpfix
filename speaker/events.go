package speaker

var (
	// entered initial state
	EVENT_INIT = "speaker/INIT"

	// session established
	EVENT_ESTABLISHED = "speaker/ESTABLISHED"

	// seen a message that is too long
	EVENT_TOO_LONG = "speaker/TOO_LONG"

	// message parse error
	EVENT_PARSE_ERROR = "speaker/PARSE_ERROR"

	// remote hold timer expired
	// val[0] = nanoseconds till last R message
	EVENT_R_TIMEOUT = "speaker/R_TIMEOUT"
)
