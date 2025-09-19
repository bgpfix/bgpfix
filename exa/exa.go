package exabgp

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
func (r *Exa) Reset() {
	*r = Exa{}
}

// ParseRoute parses an ExaBGP route command line
// Supports:
// - announce route <prefix> next-hop <ip|self> [origin <origin>] [as-path [asn...]] [med <value>] [local-preference <value>] [community [value...]]
// - withdraw route <prefix>
func (r *Exa) Parse(line string) error {
	r.Str = strings.TrimSpace(line)
	if r.Str == "" {
		return ErrEmptyLine
	}

	r.Tok = strings.Fields(r.Str)
	if len(r.Tok) < 3 {
		return ErrInvalidFormat
	}

	// Basic validation
	r.Action = r.Tok[0]
	r.Prefix = r.Tok[2]
	if r.Action != "announce" && r.Action != "withdraw" {
		return ErrInvalidAction
	} else if r.Tok[1] != "route" {
		return ErrOnlyRoute
	}

	// withdraw has no further parameters
	if r.Action == "withdraw" {
		if len(r.Tok) > 3 {
			return ErrInvalidFormat
		} else {
			return nil
		}
	}

	// Parse remaining r.Tok
	i := 3
	for i < len(r.Tok) {
		switch r.Tok[i] {
		case "next-hop":
			if i+1 >= len(r.Tok) {
				return ErrMissingValue
			}
			r.NextHop = r.Tok[i+1]
			i += 2
		case "origin":
			if i+1 >= len(r.Tok) {
				return ErrMissingValue
			}
			r.Origin = r.Tok[i+1]
			i += 2
		case "as-path":
			// Parse AS path: as-path [ 65001 65002 ]
			aspath, consumed := parseAspath(r.Tok[i+1:])
			r.ASPath = aspath
			i += consumed + 1
		case "med":
			if i+1 >= len(r.Tok) {
				return ErrMissingValue
			}
			if val, err := strconv.ParseUint(r.Tok[i+1], 10, 32); err == nil {
				med := uint32(val)
				r.MED = &med
			}
			i += 2
		case "local-preference":
			if i+1 >= len(r.Tok) {
				return ErrMissingValue
			}
			if val, err := strconv.ParseUint(r.Tok[i+1], 10, 32); err == nil {
				lp := uint32(val)
				r.LocalPref = &lp
			}
			i += 2
		case "community":
			// Parse community: community [ no-export ] or community [ 666:666 ]
			communities, consumed := parseCommunity(r.Tok[i+1:])
			r.Community = communities
			i += consumed + 1
		default:
			// Skip unknown r.Tokens
			i++
		}
	}

	return nil
}

// String converts Exa back to ExaBGP API format
func (r *Exa) String() string {
	parts := []string{r.Action, "route", r.Prefix}

	if r.NextHop != "" {
		parts = append(parts, "next-hop", r.NextHop)
	}

	if r.Origin != "" {
		parts = append(parts, "origin", r.Origin)
	}

	if len(r.ASPath) > 0 {
		asPathStr := formatAspath(r.ASPath)
		parts = append(parts, "as-path", asPathStr)
	}

	if r.MED != nil {
		parts = append(parts, "med", strconv.FormatUint(uint64(*r.MED), 10))
	}

	if r.LocalPref != nil {
		parts = append(parts, "local-preference", strconv.FormatUint(uint64(*r.LocalPref), 10))
	}

	if len(r.Community) > 0 {
		communityStr := formatCommunity(r.Community)
		parts = append(parts, "community", communityStr)
	}

	return strings.Join(parts, " ")
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

// formatAspath formats AS path as ExaBGP expects: [ 65001 65002 ]
func formatAspath(asns []uint32) string {
	if len(asns) == 0 {
		return "[ ]"
	}

	var parts []string
	for _, asn := range asns {
		parts = append(parts, strconv.FormatUint(uint64(asn), 10))
	}
	return "[ " + strings.Join(parts, " ") + " ]"
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
