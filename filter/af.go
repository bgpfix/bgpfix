package filter

import (
	"fmt"

	"github.com/bgpfix/bgpfix/afi"
)

func (e *Expr) afParse() error {
	// this supports the == operator only
	if e.Op != OP_EQ {
		return ErrOp
	} else if e.Idx != nil {
		return ErrIndex
	}

	// check value type
	switch v := e.Val.(type) {
	case afi.AFI, afi.SAFI, afi.AS:
		// all good

	case string:
		var as afi.AS
		err := as.FromJSON([]byte(v))
		if err == nil {
			e.Val = as
			break
		}

		af, err := afi.AFIString(v)
		if err == nil {
			e.Val = af
			break
		}

		sf, err := afi.SAFIString(v)
		if err == nil {
			e.Val = sf
			break
		}

		return fmt.Errorf("invalid AFI/SAFI value: %s", v)

	case int:
		if v < 0 || v > 0xffff {
			return fmt.Errorf("invalid AFI value: %d", v)
		}
		e.Val = afi.AFI(v)

	default:
		return fmt.Errorf("invalid value: %v", v)
	}

	return nil
}

func (e *Expr) afEval(ev *Eval) bool {
	as := ev.Msg.Update.AfiSafi()

	switch v := e.Val.(type) {
	case afi.AFI:
		return as.Afi() == v
	case afi.SAFI:
		return as.Safi() == v
	case afi.AS:
		return as == v
	}

	panic("unreachable")
}
