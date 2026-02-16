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

	// for ATTR_JATTR: resolve attribute name and build path
	if e.Attr == ATTR_JATTR {
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

	// convert numeric path segments to jsonparser array index format
	for i, seg := range path {
		if _, err := strconv.Atoi(seg); err == nil {
			path[i] = "[" + seg + "]"
		}
	}

	// validate value based on operator
	switch e.Op {
	case OP_PRESENT:
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

func (e *Expr) jsonEval(ev *Eval) Res {
	upper := ev.Msg.UpperJSON()
	if len(upper) == 0 {
		return RES_ABSENT // NB: should not happen
	}

	val := bj.Get(upper, e.Idx.([]string)...)
	if val == nil {
		return RES_ABSENT
	} else if e.Op == OP_PRESENT {
		return RES_TRUE
	}

	switch e.Op {
	case OP_EQ:
		return resBool(string(val) == e.Val.(string))
	case OP_LIKE:
		return resBool(e.Val.(*regexp.Regexp).Match(val))
	default:
		f, err := strconv.ParseFloat(string(val), 64)
		if err != nil {
			return RES_FALSE
		}
		return resCmp(e.Op, cmp.Compare(f, e.Val.(float64)))
	}
}
