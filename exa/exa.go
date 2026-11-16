// Package exa converts BGP routes to and from ExaBGP's text line format.
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

	LargeCommunity []string // Large community values, eg. 65000:1:2
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
	x.LargeCommunity = x.LargeCommunity[:0]
}

// exaSyntax pads list delimiters with spaces, like the ExaBGP tokeniser does
var exaSyntax = strings.NewReplacer("[", " [ ", "]", " ] ", "(", " ( ", ")", " ) ")

// Parse parses an ExaBGP route command line
// Supports:
// - announce route <prefix> next-hop <ip|self> [origin <origin>] [as-path [asn...]] [med <value>] [local-preference <value>] [community [value...]] [large-community [value...]]
// - withdraw route <prefix> (attributes, if any, are ignored)
// - "ipv4 unicast" and "ipv6 unicast" in place of "route"
func (x *Exa) Parse(line string) error {
	x.Str = strings.TrimSpace(line)
	if x.Str == "" {
		return ErrEmptyLine
	}

	x.Tok = strings.Fields(exaSyntax.Replace(x.Str))
	if len(x.Tok) < 3 {
		return ErrInvalidFormat
	}

	// Basic validation
	x.Action = x.Tok[0]
	if x.Action != "announce" && x.Action != "withdraw" {
		return ErrInvalidAction
	}

	// route, or its equivalent: ipv4 unicast / ipv6 unicast
	i := 2
	switch x.Tok[1] {
	case "route":
	case "ipv4", "ipv6":
		if x.Tok[2] != "unicast" || len(x.Tok) < 4 {
			return ErrOnlyRoute
		}
		i = 3
	default:
		return ErrOnlyRoute
	}
	x.Prefix = x.Tok[i]
	i++

	// NB: ExaBGP accepts attributes in withdraw (eg. next-hop), but does not need them
	if x.Action == "withdraw" {
		return nil
	}

	// Parse remaining r.Tok
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
			// as-path [ 65001 65002 ] or as-path 65001
			vals, consumed := parseList(x.Tok[i+1:])
			for _, v := range vals {
				if v == "(" || v == ")" {
					continue // NB: AS sets are flattened
				}
				asn, err := strconv.ParseUint(v, 10, 32)
				if err != nil {
					return ErrInvalidValue
				}
				x.ASPath = append(x.ASPath, uint32(asn))
			}
			i += consumed + 1
		case "med":
			if i+1 >= len(x.Tok) {
				return ErrMissingValue
			}
			val, err := strconv.ParseUint(x.Tok[i+1], 10, 32)
			if err != nil {
				return ErrInvalidValue
			}
			med := uint32(val)
			x.MED = &med
			i += 2
		case "local-preference":
			if i+1 >= len(x.Tok) {
				return ErrMissingValue
			}
			val, err := strconv.ParseUint(x.Tok[i+1], 10, 32)
			if err != nil {
				return ErrInvalidValue
			}
			lp := uint32(val)
			x.LocalPref = &lp
			i += 2
		case "community":
			// community [ no-export 666:666 ] or community 666:666
			vals, consumed := parseList(x.Tok[i+1:])
			x.Community = parseCommunity(x.Community, vals)
			i += consumed + 1
		case "large-community":
			// large-community [ 65000:1:2 ] or large-community 65000:1:2
			vals, consumed := parseList(x.Tok[i+1:])
			x.LargeCommunity = append(x.LargeCommunity, vals...)
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

	if len(x.LargeCommunity) > 0 {
		x.Tok = append(x.Tok, "large-community", formatCommunity(x.LargeCommunity))
	}

	x.Str = strings.Join(x.Tok, " ")
	return x.Str
}

// parseList returns the values of a list like [ a b ], or a single value,
// and the number of tokens consumed.
func parseList(tokens []string) ([]string, int) {
	if len(tokens) == 0 {
		return nil, 0
	} else if tokens[0] != "[" {
		return tokens[:1], 1
	}

	for i := 1; i < len(tokens); i++ {
		if tokens[i] == "]" {
			return tokens[1:i], i + 1
		}
	}
	return tokens[1:], len(tokens) // NB: missing ]
}

// parseCommunity appends communities in vals to dst, normalizing well-known names
func parseCommunity(dst []string, vals []string) []string {
	for _, community := range vals {
		normalized := strings.ToLower(strings.ReplaceAll(community, "_", "-"))
		switch normalized {
		case "no-export", "noexport":
			dst = append(dst, "no-export")
		case "no-advertise", "noadvertise":
			dst = append(dst, "no-advertise")
		case "no-export-subconfed", "noexportsubconfed":
			dst = append(dst, "no-export-subconfed")
		case "no-peer", "nopeer":
			dst = append(dst, "no-peer")
		case "blackhole":
			dst = append(dst, "blackhole")
		default:
			dst = append(dst, community)
		}
	}
	return dst
}

// formatCommunity formats communities as ExaBGP expects: [ no-export ] or [ 123:456 ]
func formatCommunity(communities []string) string {
	if len(communities) == 0 {
		return "[ ]"
	}
	return "[ " + strings.Join(communities, " ") + " ]"
}
