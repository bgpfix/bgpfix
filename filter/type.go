package filter

import (
	"fmt"

	"github.com/bgpfix/bgpfix/msg"
)

func (e *Expr) typeParse() error {
	// this supports the == operator only
	if e.Op != OP_EQ {
		return ErrOp
	} else if e.Idx != nil {
		return ErrIndex
	}

	switch v := e.Val.(type) {
	case msg.Type:
		// all good

	case string:
		t, err := msg.TypeString(v)
		if err != nil {
			return fmt.Errorf("invalid BGP message type: %s", v)
		}
		e.Val = t

	case int:
		e.Val = msg.Type(v)

	default:
		return fmt.Errorf("invalid type: %v", v)
	}

	e.Types = true
	return nil
}

func (e *Expr) typeEval(ev *Eval) bool {
	return ev.Msg.Type == e.Val.(msg.Type)
}
