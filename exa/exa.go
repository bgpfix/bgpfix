package exa

import (
	"strconv"
	"strings"
)

// Exa represents an ExaBGP route announcement/withdrawal
// Focuses on the most commonly used attributes (80/20 approach)
type Exa struct {
	Str string   // parsed line (optional)
	Tok []string // all tokens in line (optional)

	Action    string   // announce or withdraw
	Prefix    string   // IP prefix (e.g., "10.0.0.1/24")
	NextHop   string   // next-hop IP address or "self"
	Origin    string   // IGP, EGP, INCOMPLETE (optional)
	ASPath    []uint32 // AS path sequence (optional)
	MED       *uint32  // Multi-Exit Discriminator (optional)
	LocalPref *uint32  // Local preference (optional)
	Community []string // Community values in brackets [no-export] or [123:456]
}

// NewExa returns a new, empty Exa instance
func NewExa() *Exa {
	return &Exa{}
}

// NewExaLine creates a new Exa and parses the given command line
func NewExaLine(line string) (*Exa, error) {
	r := NewExa()
	if err := r.Parse(line); err != nil {
		return nil, err
	} else {
		return r, nil
	}
}

// Reset clears all fields in Exa
func (x *Exa) Reset() {
	x.Str = ""
	x.Tok = x.Tok[:0]
	x.Action = ""
	x.Prefix = ""
	x.NextHop = ""
	x.Origin = ""
	x.ASPath = x.ASPath[:0]
	x.MED = nil
	x.LocalPref = nil
	x.Community = x.Community[:0]
}

// ParseRoute parses an ExaBGP route command line
// Supports:
// - announce route <prefix> next-hop <ip|self> [origin <origin>] [as-path [asn...]] [med <value>] [local-preference <value>] [community [value...]]
// - withdraw route <prefix>
func (x *Exa) Parse(line string) error {
	x.Str = strings.TrimSpace(line)
	if x.Str == "" {
		return ErrEmptyLine
	}

	x.Tok = strings.Fields(x.Str)
	if len(x.Tok) < 3 {
		return ErrInvalidFormat
	}

	// Basic validation
	x.Action = x.Tok[0]
	x.Prefix = x.Tok[2]
	if x.Action != "announce" && x.Action != "withdraw" {
		return ErrInvalidAction
	} else if x.Tok[1] != "route" {
		return ErrOnlyRoute
	}

	// withdraw has no further parameters
	if x.Action == "withdraw" {
		if len(x.Tok) > 3 {
			return ErrInvalidFormat
		} else {
			return nil
		}
	}

	// Parse remaining r.Tok
	i := 3
	for i < len(x.Tok) {
		switch x.Tok[i] {
		case "next-hop":
			if i+1 >= len(x.Tok) {
				return ErrMissingValue
			}
			x.NextHop = x.Tok[i+1]
			i += 2
		case "origin":
			if i+1 >= len(x.Tok) {
				return ErrMissingValue
			}
			x.Origin = x.Tok[i+1]
			i += 2
		case "as-path":
			// Parse AS path: as-path [ 65001 65002 ]
			aspath, consumed := parseAspath(x.Tok[i+1:])
			x.ASPath = aspath
			i += consumed + 1
		case "med":
			if i+1 >= len(x.Tok) {
				return ErrMissingValue
			}
			if val, err := strconv.ParseUint(x.Tok[i+1], 10, 32); err == nil {
				med := uint32(val)
				x.MED = &med
			}
			i += 2
		case "local-preference":
			if i+1 >= len(x.Tok) {
				return ErrMissingValue
			}
			if val, err := strconv.ParseUint(x.Tok[i+1], 10, 32); err == nil {
				lp := uint32(val)
				x.LocalPref = &lp
			}
			i += 2
		case "community":
			// Parse community: community [ no-export ] or community [ 666:666 ]
			communities, consumed := parseCommunity(x.Tok[i+1:])
			x.Community = communities
			i += consumed + 1
		default:
			// Skip unknown r.Tokens
			i++
		}
	}

	return nil
}

// String converts Exa back to ExaBGP API format
func (x *Exa) String() string {
	if len(x.Str) > 0 {
		return x.Str
	}

	x.Tok = append(x.Tok[:0], x.Action, "route", x.Prefix)

	if x.NextHop != "" {
		x.Tok = append(x.Tok, "next-hop", x.NextHop)
	}

	if x.Origin != "" {
		x.Tok = append(x.Tok, "origin", x.Origin)
	}

	if len(x.ASPath) > 0 {
		x.Tok = append(x.Tok, "as-path", "[")
		for _, asn := range x.ASPath {
			x.Tok = append(x.Tok, strconv.FormatUint(uint64(asn), 10))
		}
		x.Tok = append(x.Tok, "]")
	}

	if x.MED != nil {
		x.Tok = append(x.Tok, "med", strconv.FormatUint(uint64(*x.MED), 10))
	}

	if x.LocalPref != nil {
		x.Tok = append(x.Tok, "local-preference", strconv.FormatUint(uint64(*x.LocalPref), 10))
	}

	if len(x.Community) > 0 {
		communityStr := formatCommunity(x.Community)
		x.Tok = append(x.Tok, "community", communityStr)
	}

	x.Str = strings.Join(x.Tok, " ")
	return x.Str
}

// parseAspath parses AS path from tokens like: [ 65001 65002 ]
func parseAspath(tokens []string) ([]uint32, int) {
	if len(tokens) == 0 || tokens[0] != "[" {
		return nil, 0
	}

	var asns []uint32
	consumed := 1 // for opening [

	for i := 1; i < len(tokens); i++ {
		consumed++
		if tokens[i] == "]" {
			break
		}
		if asn, err := strconv.ParseUint(tokens[i], 10, 32); err == nil {
			asns = append(asns, uint32(asn))
		}
	}

	return asns, consumed
}

// parseCommunity parses community from tokens like: [ no-export ] or [ 666:666 ]
func parseCommunity(tokens []string) ([]string, int) {
	if len(tokens) == 0 || tokens[0] != "[" {
		return nil, 0
	}

	var communities []string
	consumed := 1 // for opening [

	for i := 1; i < len(tokens); i++ {
		consumed++
		if tokens[i] == "]" {
			break
		}

		// Normalize community name to canonical form
		community := tokens[i]
		normalized := strings.ToLower(strings.ReplaceAll(community, "_", "-"))

		switch normalized {
		case "no-export", "noexport":
			communities = append(communities, "no-export")
		case "no-advertise", "noadvertise":
			communities = append(communities, "no-advertise")
		case "no-export-subconfed", "noexportsubconfed":
			communities = append(communities, "no-export-subconfed")
		case "no-peer", "nopeer":
			communities = append(communities, "no-peer")
		case "blackhole":
			communities = append(communities, "blackhole")
		default:
			// For AS:value format, keep original (case-sensitive for numbers)
			communities = append(communities, community)
		}
	}

	return communities, consumed
}

// formatCommunity formats communities as ExaBGP expects: [ no-export ] or [ 123:456 ]
func formatCommunity(communities []string) string {
	if len(communities) == 0 {
		return "[ ]"
	}
	return "[ " + strings.Join(communities, " ") + " ]"
}
