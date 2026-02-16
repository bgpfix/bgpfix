package filter

import (
	"fmt"
	"regexp"
)

func (e *Expr) tagParse() error {
	// check operator (TRUE/EQ/LIKE), make value string or regexp
	switch e.Op {
	case OP_PRESENT:
		// non-empty tag or tags
	case OP_EQ:
		if _, ok := e.Val.(string); !ok {
			e.Val = fmt.Sprintf("%v", e.Val)
		}
	case OP_LIKE: // value is a string
		re, err := regexp.Compile(e.Val.(string))
		if err != nil {
			return fmt.Errorf("invalid regex: %w", err)
		}
		e.Val = re
	default:
		return ErrOp
	}

	// make index either nil or string
	if e.Idx != nil {
		if _, ok := e.Idx.(string); !ok {
			e.Idx = fmt.Sprintf("%v", e.Idx)
		}
	}

	e.Types = true
	return nil
}

func (e *Expr) tagEval(ev *Eval) Res {
	tags := ev.PipeTags
	if len(tags) == 0 {
		return RES_ABSENT
	}

	// check_val checks specific tag value
	check_val := func(val string) bool {
		switch e.Op {
		case OP_PRESENT:
			return val != ""
		case OP_EQ:
			return val == e.Val
		case OP_LIKE:
			return e.Val.(*regexp.Regexp).MatchString(val)
		default:
			panic("unreachable")
		}
	}

	// specific tag key?
	if e.Idx != nil {
		val := tags[e.Idx.(string)]
		if val == "" {
			return RES_ABSENT
		}
		return resBool(check_val(val))
	}

	// look for any tag match
	for _, val := range tags {
		if check_val(val) {
			return RES_TRUE
		}
	}
	return RES_FALSE
}
