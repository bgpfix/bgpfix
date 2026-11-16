package exa

import (
	"bytes"
	"strings"
)

// IsExaBytes checks if the given byte slice looks like an ExaBGP command line.
// Requires at least 8 bytes to check for "announce", "withdraw", or "neighbor".
func IsExaBytes(line []byte) bool {
	line = bytes.TrimSpace(line)
	switch {
	case len(line) < 8:
		return false
	case string(line[:8]) == "announce":
		return true
	case string(line[:8]) == "withdraw", string(line[:8]) == "neighbor":
		return true
	default:
		return false
	}
}

// IsExaString checks if the given byte slice looks like an ExaBGP command line.
// Requires at least 8 bytes to check for "announce", "withdraw", or "neighbor".
func IsExaString(line string) bool {
	line = strings.TrimSpace(line)
	switch {
	case len(line) < 8:
		return false
	case line[:8] == "announce":
		return true
	case line[:8] == "withdraw", line[:8] == "neighbor":
		return true
	default:
		return false
	}
}
