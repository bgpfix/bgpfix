package afi

import "fmt"

// ParseAFI is like AFIString, but also accepts the "AFI(n)" form that
// String() prints for values not in the enum, so that JSON round-trips.
func ParseAFI(s string) (AFI, error) {
	v, err := AFIString(s)
	if err != nil {
		var n uint16
		if _, err2 := fmt.Sscanf(s, "AFI(%d)", &n); err2 == nil {
			return AFI(n), nil
		}
	}
	return v, err
}

// ParseSAFI is like SAFIString, but also accepts the "SAFI(n)" form.
func ParseSAFI(s string) (SAFI, error) {
	v, err := SAFIString(s)
	if err != nil {
		var n uint8
		if _, err2 := fmt.Sscanf(s, "SAFI(%d)", &n); err2 == nil {
			return SAFI(n), nil
		}
	}
	return v, err
}
