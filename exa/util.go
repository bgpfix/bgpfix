package exa

import (
	"bytes"
	"strings"
)

// IsExaBytes checks if the given byte slice looks like an ExaBGP command line
func IsExaBytes(line []byte) bool {
	line = bytes.TrimSpace(line)
	switch {
	case len(line) < 8:
		return false
	case string(line[:8]) == "announce":
		return true
	case string(line[:8]) == "withdraw":
		return true
	default:
		return false
	}
}

// IsExaString checks if the given byte slice looks like an ExaBGP command line
func IsExaString(line string) bool {
	line = strings.TrimSpace(line)
	switch {
	case len(line) < 8:
		return false
	case line[:8] == "announce":
		return true
	case line[:8] == "withdraw":
		return true
	default:
		return false
	}
}
