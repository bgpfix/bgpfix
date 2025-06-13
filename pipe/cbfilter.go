package pipe

type CbFilterMode = int

const (
	// callback filter disabled
	CBFILTER_NONE CbFilterMode = iota

	// skip if callback id == value
	CBFILTER_EQ

	// skip if callback id > value
	CBFILTER_GT

	// skip if callback id < value
	CBFILTER_LT

	// skip if callback id >= value
	CBFILTER_GE

	// skip if callback id <= value
	CBFILTER_LE

	// skip if callback id != value
	CBFILTER_NE

	// skip all callbacks
	CBFILTER_ALL
)

func cbfilterSkip(li *Input, cb *Callback) bool {
	cbid := cb.Id
	if cbid == 0 {
		return false
	}

	val, ok := li.CbFilterValue.(int)
	if !ok {
		return false
	}

	switch li.CbFilter {
	case CBFILTER_NONE:
		return false
	case CBFILTER_EQ:
		return cbid == val
	case CBFILTER_GT:
		return cbid > val
	case CBFILTER_LT:
		return cbid < val
	case CBFILTER_GE:
		return cbid >= val
	case CBFILTER_LE:
		return cbid <= val
	case CBFILTER_NE:
		return cbid != val
	case CBFILTER_ALL:
		return true
	}

	return false
}
