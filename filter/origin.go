package filter

import (
	"fmt"
	"strings"
)

func (e *Expr) originParse() error {
	if e.Idx != nil {
		return ErrIndex
	}

	switch e.Op {
	case OP_PRESENT:
		return nil
	case OP_EQ:
		// accept int or string
		switch v := e.Val.(type) {
		case int:
			if v < 0 || v > 2 {
				return fmt.Errorf("invalid origin value: %d (0=IGP, 1=EGP, 2=INCOMPLETE)", v)
			}
			e.Val = byte(v)
		case string:
			switch strings.ToLower(v) {
			case "igp", "i":
				e.Val = byte(0)
			case "egp", "e":
				e.Val = byte(1)
			case "incomplete", "?":
				e.Val = byte(2)
			default:
				return fmt.Errorf("invalid origin value: %s (use igp/egp/incomplete)", v)
			}
		default:
			return fmt.Errorf("invalid origin value: %v", v)
		}
	default:
		return ErrOp
	}
	return nil
}

func (e *Expr) originEval(ev *Eval) Res {
	origin, ok := ev.Msg.Update.Origin()
	if !ok {
		return RES_ABSENT
	}
	if e.Op == OP_PRESENT {
		return RES_TRUE
	}
	return resBool(origin == e.Val.(byte))
}
