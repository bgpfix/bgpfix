package pipe

type FilterMode = int

const (
	// callback filter disabled
	FILTER_NONE FilterMode = iota

	// skip if callback id == value
	FILTER_EQ

	// skip if callback id > value
	FILTER_GT

	// skip if callback id < value
	FILTER_LT

	// skip if callback id >= value
	FILTER_GE

	// skip if callback id <= value
	FILTER_LE

	// skip if callback id != value
	FILTER_NE

	// skip all callbacks
	FILTER_ALL
)

func filterSkip(li *Input, cb *Callback) bool {
	cbid := cb.Id
	val, _ := li.FilterValue.(int)

	switch li.CallbackFilter {
	case FILTER_NONE:
		return false
	case FILTER_EQ:
		return cbid == val
	case FILTER_GT:
		return cbid > val
	case FILTER_LT:
		return cbid < val
	case FILTER_GE:
		return cbid >= val
	case FILTER_LE:
		return cbid <= val
	case FILTER_NE:
		return cbid != val
	case FILTER_ALL:
		return true
	}

	return false
}
