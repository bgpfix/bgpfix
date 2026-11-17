package filter

import "fmt"

var (
	ErrEmpty     = fmt.Errorf("empty filter")
	ErrExpr      = fmt.Errorf("invalid expression")
	ErrUnmatched = fmt.Errorf("unmatched parentheses")
	ErrAttr      = fmt.Errorf("invalid attribute")
	ErrIndex     = fmt.Errorf("invalid index")
	ErrOp        = fmt.Errorf("invalid operator")
	ErrValue     = fmt.Errorf("invalid value")
	ErrOpValue   = fmt.Errorf("operator needs value")
	ErrLogic     = fmt.Errorf("expecting logical operator")
)
