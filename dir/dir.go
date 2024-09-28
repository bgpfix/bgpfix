// Package dir represents BGP message direction.
//
// Exported to a separate package in order to avoid loops.
package dir

// BGP message direction
type Dir byte

const (
	DIR_L  Dir = 0b01 // L direction: "left" or "local"
	DIR_R  Dir = 0b10 // R direction: "right" or "remote"
	DIR_LR Dir = 0b11 // LR direction: both "left" and "right"
)

// Flip returns the opposite direction
func (d Dir) Flip() Dir {
	switch d {
	case DIR_L:
		return DIR_R
	case DIR_R:
		return DIR_L
	default:
		return 0
	}
}

// String converts Dir to string
func (d Dir) String() string {
	switch d {
	case DIR_L:
		return "L"
	case DIR_R:
		return "R"
	case DIR_LR:
		return "LR"
	default:
		return "?"
	}
}

// DirString converts string to Dir
func DirString(s string) (Dir, error) {
	switch s {
	case "L", "l":
		return DIR_L, nil
	case "R", "r":
		return DIR_R, nil
	case "LR", "lr", "Lr", "lR":
		return DIR_LR, nil
	default:
		return 0, ErrValue
	}
}
