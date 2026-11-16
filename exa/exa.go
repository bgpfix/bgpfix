// Package exa converts BGP routes to and from ExaBGP's text line format.
package exa

import (
	"fmt"
	"strconv"
	"strings"
)

// Exa represents an ExaBGP route announcement/withdrawal
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

	LargeCommunity  []string // large communities, eg. 65000:1:2
	ExtCommunity    []string // extended communities, eg. target:65000:1 or 0x0002fde800000001
	AtomicAggregate bool     // atomic-aggregate
	Aggregator      string   // aggregator, eg. 65000:192.0.2.1
	OriginatorID    string   // originator-id, eg. 192.0.2.1
	ClusterList     []string // cluster-list, eg. 192.0.2.1
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
	x.ExtCommunity = x.ExtCommunity[:0]
	x.AtomicAggregate = false
	x.Aggregator = ""
	x.OriginatorID = ""
	x.ClusterList = x.ClusterList[:0]
}

// exaSyntax pads list delimiters with spaces, like the ExaBGP tokeniser does
var exaSyntax = strings.NewReplacer("[", " [ ", "]", " ] ", "(", " ( ", ")", " ) ")

// Parse parses an ExaBGP route command line:
//
//	announce route <prefix> [next-hop <ip|self>] [<attribute> ...]
//	withdraw route <prefix> (attributes, if any, are ignored)
//
// "ipv4 unicast" and "ipv6 unicast" can be used in place of "route".
// A leading "neighbor <ip> ..." selector is skipped.
func (x *Exa) Parse(line string) error {
	x.Str = strings.TrimSpace(line)
	if x.Str == "" {
		return ErrEmptyLine
	}
	x.Tok = strings.Fields(exaSyntax.Replace(x.Str))
	tok := x.Tok

	// skip the neighbor selector, if any
	if tok[0] == "neighbor" {
		for len(tok) > 0 && tok[0] != "announce" && tok[0] != "withdraw" {
			tok = tok[1:]
		}
	}
	if len(tok) < 3 {
		return ErrInvalidFormat
	}

	// Basic validation
	x.Action = tok[0]
	if x.Action != "announce" && x.Action != "withdraw" {
		return ErrInvalidAction
	}

	// route, or its equivalent: ipv4 unicast / ipv6 unicast
	switch tok[1] {
	case "route":
		tok = tok[2:]
	case "ipv4", "ipv6":
		if tok[2] != "unicast" || len(tok) < 4 {
			return ErrOnlyRoute
		}
		tok = tok[3:]
	default:
		return ErrOnlyRoute
	}
	x.Prefix, tok = tok[0], tok[1:]

	// NB: ExaBGP accepts attributes in withdraw (eg. next-hop), but does not need them
	if x.Action == "withdraw" {
		return nil
	}

	// parse the attributes
	for len(tok) > 0 {
		var key string
		key, tok = tok[0], tok[1:]

		// attributes with no value
		if key == "atomic-aggregate" {
			x.AtomicAggregate = true
			continue
		}

		// take the value(s): [ a b ], ( a ), or a
		vals, n := parseList(tok)
		if len(vals) == 0 && key != "as-path" {
			return ErrMissingValue
		}
		tok = tok[n:]

		switch key {
		case "next-hop":
			x.NextHop = vals[0]
		case "origin":
			x.Origin = vals[0]
		case "as-path":
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
		case "med", "local-preference":
			val, err := strconv.ParseUint(vals[0], 10, 32)
			if err != nil {
				return ErrInvalidValue
			}
			v := uint32(val)
			if key == "med" {
				x.MED = &v
			} else {
				x.LocalPref = &v
			}
		case "community":
			x.Community = parseCommunity(x.Community, vals)
		case "large-community":
			x.LargeCommunity = append(x.LargeCommunity, vals...)
		case "extended-community":
			x.ExtCommunity = append(x.ExtCommunity, vals...)
		case "aggregator":
			x.Aggregator = vals[0]
		case "originator-id":
			x.OriginatorID = vals[0]
		case "cluster-list":
			x.ClusterList = append(x.ClusterList, vals...)
		default:
			// NB: do not announce a route without what was asked for
			return fmt.Errorf("%w: %s", ErrUnsupported, key)
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

	if len(x.ExtCommunity) > 0 {
		x.Tok = append(x.Tok, "extended-community", formatCommunity(x.ExtCommunity))
	}

	if x.AtomicAggregate {
		x.Tok = append(x.Tok, "atomic-aggregate")
	}

	if x.Aggregator != "" {
		x.Tok = append(x.Tok, "aggregator", "(", x.Aggregator, ")")
	}

	if x.OriginatorID != "" {
		x.Tok = append(x.Tok, "originator-id", x.OriginatorID)
	}

	if len(x.ClusterList) > 0 {
		x.Tok = append(x.Tok, "cluster-list", formatCommunity(x.ClusterList))
	}

	x.Str = strings.Join(x.Tok, " ")
	return x.Str
}

// parseList returns the values of a list like [ a b ] or ( a ), or a single value,
// and the number of tokens consumed.
func parseList(tokens []string) ([]string, int) {
	if len(tokens) == 0 {
		return nil, 0
	}

	end := ""
	switch tokens[0] {
	case "[":
		end = "]"
	case "(":
		end = ")"
	default:
		return tokens[:1], 1
	}

	for i := 1; i < len(tokens); i++ {
		if tokens[i] == end {
			return tokens[1:i], i + 1
		}
	}
	return tokens[1:], len(tokens) // NB: not closed
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
