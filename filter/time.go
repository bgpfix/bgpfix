package filter

import (
	"fmt"
	"regexp"
	"time"

	"github.com/itlightning/dateparse"
)

func (e *Expr) timeParse() error {
	// no index allowed
	if e.Idx != nil {
		return ErrIndex
	}

	switch e.Op {
	case OP_PRESENT:
		// ok
	case OP_LIKE:
		re, err := regexp.Compile(e.Val.(string))
		if err != nil {
			return fmt.Errorf("invalid regex: %w", err)
		}
		e.Val = re
	case OP_EQ, OP_LT, OP_LE, OP_GT, OP_GE:
		t, err := dateparse.ParseAny(fmt.Sprintf("%v", e.Val))
		if err != nil {
			return err
		}
		e.Val = t
	default:
		return ErrOp
	}

	e.Types = true
	return nil
}

func (e *Expr) timeEval(ev *Eval) Res {
	if ev.Msg.Time.IsZero() {
		return RES_ABSENT
	} else if e.Op == OP_PRESENT {
		return RES_TRUE
	}

	switch e.Op {
	case OP_LIKE:
		ts := ev.getTime()
		return resBool(e.Val.(*regexp.Regexp).MatchString(ts))
	default:
		return resCmp(e.Op, ev.Msg.Time.Compare(e.Val.(time.Time)))
	}
}
