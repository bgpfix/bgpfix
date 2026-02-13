package filter

import (
	"fmt"
	"regexp"
	"strings"
)

func (e *Expr) timeParse() error {
	// no index allowed
	if e.Idx != nil {
		return ErrIndex
	}

	switch e.Op {
	case OP_TRUE:
		// ok
	case OP_EQ:
		if _, ok := e.Val.(string); !ok {
			e.Val = fmt.Sprintf("%v", e.Val)
		}
	case OP_LIKE:
		re, err := regexp.Compile(e.Val.(string))
		if err != nil {
			return fmt.Errorf("invalid regex: %w", err)
		}
		e.Val = re
	case OP_LT, OP_LE, OP_GT, OP_GE:
		if _, ok := e.Val.(string); !ok {
			e.Val = fmt.Sprintf("%v", e.Val)
		}
	default:
		return ErrOp
	}

	e.Types = true
	return nil
}

func (e *Expr) timeEval(ev *Eval) bool {
	if ev.Msg.Time.IsZero() {
		return false
	}
	if e.Op == OP_TRUE {
		return true
	}

	ts := ev.getTime()
	switch e.Op {
	case OP_EQ:
		return ts == e.Val.(string)
	case OP_LIKE:
		return e.Val.(*regexp.Regexp).MatchString(ts)
	default:
		return cmpOp(strings.Compare(ts, e.Val.(string)), e.Op)
	}
}
