package rpki

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"net/netip"
	"strconv"
	"strings"
)

// Parse parses RPKI data in JSON or CSV format (auto-detected) into the
// pending set. Call Flush first to start from scratch, and Apply after
// to publish the result.
func (c *Cache) Parse(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return fmt.Errorf("empty RPKI data")
	} else if data[0] == '{' {
		return c.ParseJSON(data)
	} else {
		return c.ParseCSV(data)
	}
}

// parseASN parses an ASN, accepting an optional "AS" prefix.
func parseASN(s string) (uint32, error) {
	s = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(s)), "as")
	n, err := strconv.ParseUint(s, 10, 32)
	return uint32(n), err
}

// ParseJSON parses Routinator/rpki-client JSON with VRPs and ASPA records
// into the pending set. Malformed JSON or unexpected field types (eg. a
// string customer_asid) return an error; well-typed entries with invalid
// values (bad prefix, out-of-range maxLength/ASN) are skipped with a warning.
func (c *Cache) ParseJSON(data []byte) error {
	var doc struct {
		ROAs []struct {
			Prefix    string `json:"prefix"`
			MaxLength int    `json:"maxLength"`
			ASN       any    `json:"asn"`
		} `json:"roas"`
		ASPAs []struct {
			CustomerASID  uint32   `json:"customer_asid"`
			ProviderASIDs []uint32 `json:"provider_asids"` // Routinator
			Providers     []uint32 `json:"providers"`      // rpki-client
		} `json:"aspas"`
	}

	if err := json.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("JSON parse error: %w", err)
	}

	// NB: lock once for the whole batch
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, roa := range doc.ROAs {
		prefix, err := netip.ParsePrefix(roa.Prefix)
		if err != nil {
			c.Warn().Str("prefix", roa.Prefix).Msg("invalid prefix, skipping")
			continue
		}

		if roa.MaxLength < 0 || roa.MaxLength > 128 {
			c.Warn().Str("prefix", roa.Prefix).Int("maxLength", roa.MaxLength).Msg("maxLength out of range, skipping")
			continue
		}

		var asn uint32
		switch v := roa.ASN.(type) {
		case string:
			asn, err = parseASN(v)
			if err != nil {
				c.Warn().Str("asn", v).Msg("invalid ASN, skipping")
				continue
			}
		case float64:
			if v < 0 || v > math.MaxUint32 || v != math.Trunc(v) {
				c.Warn().Float64("asn", v).Msg("ASN out of range, skipping")
				continue
			}
			asn = uint32(v)
		default:
			c.Warn().Str("asn", fmt.Sprint(roa.ASN)).Msg("invalid ASN type, skipping")
			continue
		}

		c.addVRP(true, prefix, uint8(roa.MaxLength), asn)
	}

	for _, aspa := range doc.ASPAs {
		// NB: Routinator uses provider_asids, rpki-client uses providers.
		// rpki-client emits [0] for "no providers" — addASPA filters zeros.
		provs := aspa.ProviderASIDs
		if provs == nil {
			provs = aspa.Providers
		}
		c.addASPA(true, aspa.CustomerASID, provs)
	}

	return nil
}

// ParseCSV parses CSV VRP data (prefix,maxLength,asn) into the pending set.
// The Routinator column order (asn,prefix,maxLength[,trustAnchor]) is
// auto-detected per line. Invalid lines are skipped with a warning.
func (c *Cache) ParseCSV(data []byte) error {
	lines := strings.Split(string(data), "\n")

	// NB: lock once for the whole batch
	c.mu.Lock()
	defer c.mu.Unlock()

	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' {
			continue
		}

		if i == 0 && strings.Contains(strings.ToLower(line), "prefix") {
			continue
		}

		parts := strings.Split(line, ",")
		if len(parts) < 3 {
			c.Warn().Int("line", i+1).Msg("invalid CSV line, skipping")
			continue
		}

		// column order: native prefix,maxLength,asn; if the first field is
		// not a prefix, assume Routinator's asn,prefix,maxLength[,TA]
		p0, p1, p2 := parts[0], parts[1], parts[2]
		if _, err := netip.ParsePrefix(strings.TrimSpace(p0)); err != nil {
			p0, p1, p2 = p1, p2, parts[0]
		}

		prefix, err := netip.ParsePrefix(strings.TrimSpace(p0))
		if err != nil {
			c.Warn().Int("line", i+1).Err(err).Str("prefix", p0).Msg("invalid prefix, skipping")
			continue
		}

		maxLen, err := strconv.Atoi(strings.TrimSpace(p1))
		if err != nil {
			c.Warn().Int("line", i+1).Err(err).Msg("invalid maxLength, skipping")
			continue
		}
		if maxLen < 0 || maxLen > 128 {
			c.Warn().Int("line", i+1).Int("maxLength", maxLen).Msg("maxLength out of range, skipping")
			continue
		}

		asn, err := parseASN(p2)
		if err != nil {
			c.Warn().Err(err).Int("line", i+1).Msg("invalid ASN, skipping")
			continue
		}

		c.addVRP(true, prefix, uint8(maxLen), asn)
	}

	return nil
}
