package filter

import (
	"cmp"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/bgpfix/bgpfix/attrs"
	bj "github.com/bgpfix/bgpfix/json"
)

func (e *Expr) jsonParse() error {
	// require index (path)
	if e.Idx == nil {
		return ErrIndex
	}

	// convert index to string, split on "."
	path := strings.Split(fmt.Sprintf("%v", e.Idx), ".")

	// for ATTR_JSONATTR: resolve attribute name and build path
	if e.Attr == ATTR_JSONATTR {
		name := strings.ToUpper(path[0])

		// try with ATTR_ prefix first, then without
		code, err := attrs.CodeString("ATTR_" + name)
		if err != nil {
			code, err = attrs.CodeString(name)
		}
		if err != nil {
			return fmt.Errorf("unknown attribute: %s", path[0])
		}

		// use proper case name from CodeName
		attrName := attrs.CodeName[code]

		// build path: attrs -> NAME -> value -> remaining subpath
		newPath := []string{"attrs", attrName, "value"}
		if len(path) > 1 {
			newPath = append(newPath, path[1:]...)
		}
		path = newPath
	}

	// validate value based on operator
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
		switch v := e.Val.(type) {
		case int:
			e.Val = float64(v)
		case float64:
			// already good
		default:
			return fmt.Errorf("numeric operator requires numeric value")
		}
	default:
		return ErrOp
	}

	// store path
	e.Idx = path

	// json works on all message types
	if e.Attr == ATTR_JSON {
		e.Types = true
	}

	return nil
}

func (e *Expr) jsonEval(ev *Eval) bool {
	upper := ev.getUpper()
	if upper == nil {
		return false
	}

	path := e.Idx.([]string)
	val := bj.Get(upper, path...)
	if val == nil {
		return false
	}

	switch e.Op {
	case OP_TRUE:
		return true
	case OP_EQ:
		return string(val) == e.Val.(string)
	case OP_LIKE:
		return e.Val.(*regexp.Regexp).Match(val)
	default:
		f, err := strconv.ParseFloat(string(val), 64)
		if err != nil {
			return false
		}
		return cmpOp(cmp.Compare(f, e.Val.(float64)), e.Op)
	}
}
