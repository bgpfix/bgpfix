package msg

import (
	"strings"
	"testing"

	"github.com/bgpfix/bgpfix/afi"
	"github.com/bgpfix/bgpfix/caps"
	"github.com/bgpfix/bgpfix/nlri"
)

func guessCaps() caps.Caps {
	var cps caps.Caps
	cps.Use(caps.CAP_ADDPATH_GUESS)
	return cps
}

// ORIGIN + AS_PATH + NEXT_HOP
var guessAttrs = []byte{0x40, 1, 1, 0, 0x40, 2, 4, 2, 1, 0xfd, 0xe8, 0x40, 3, 4, 10, 0, 0, 1}

func guessUpdate(nlri []byte, ats ...byte) []byte {
	ats = append(append([]byte{}, guessAttrs...), ats...)
	b := []byte{0, 0, 0, byte(len(ats))}
	b = append(b, ats...)
	return append(b, nlri...)
}

func TestAddPathGuess(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		cps     caps.Caps
		want    string // Reach or MP_REACH prefixes
		addpath bool   // ParseAddPath set, with IPv4 or IPv6 unicast on
	}{
		{"ipv4 path id", guessUpdate([]byte{0, 0, 0, 1, 24, 192, 0, 2}), guessCaps(),
			"192.0.2.0/24", true},
		{"ipv4 two path ids", guessUpdate([]byte{0, 0, 0, 1, 24, 192, 0, 2, 0, 0, 0, 2, 16, 10, 1}), guessCaps(),
			"192.0.2.0/24 10.1.0.0/16", true},
		{"ipv4 plain", guessUpdate([]byte{24, 192, 0, 2, 8, 10}), guessCaps(),
			"192.0.2.0/24 10.0.0.0/8", false},
		{"ipv6 mp_reach path id", guessUpdate(nil,
			0x80, 14, 30, 0, 2, 1, 16, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0,
			0, 0, 0, 7, 32, 0x20, 0x01, 0x0d, 0xb8), guessCaps(),
			"2001:db8::/32", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewMsg()
			m.Type = UPDATE
			m.Data = tt.data
			if err := m.Parse(tt.cps); err != nil {
				t.Fatal(err)
			}

			var got []nlri.Prefix
			as := afi.AS_IPV4_UNICAST
			if pfx := m.Update.ReachMP().Prefixes(); pfx != nil {
				got, as = pfx.Prefixes, afi.AS_IPV6_UNICAST
			} else {
				got = m.Update.Reach
			}
			s := ""
			for i, p := range got {
				if i > 0 {
					s += " "
				}
				s += p.Prefix.String()
			}
			if s != tt.want {
				t.Errorf("prefixes = %q, want %q", s, tt.want)
			}
			if has := m.ParseAddPath != nil && m.ParseAddPath.Has(as); has != tt.addpath {
				t.Errorf("ParseAddPath = %v, want addpath=%v", m.ParseAddPath, tt.addpath)
			}
		})
	}
}

// without the pseudo-capability, nothing is guessed
func TestAddPathNoGuess(t *testing.T) {
	m := NewMsg()
	m.Type = UPDATE
	m.Data = guessUpdate([]byte{0, 0, 0, 1, 24, 192, 0, 2})
	if err := m.Parse(caps.Caps{}); err == nil {
		t.Errorf("parsed without guessing: %v", m.Update.Reach)
	}
}

// a truncated MP_REACH (AFI+SAFI only) must not panic the guesser
func TestAddPathGuessShortMP(t *testing.T) {
	m := NewMsg()
	m.Type = UPDATE
	m.Data = guessUpdate(nil, 0x80, 14, 3, 0, 2, 1)
	if err := m.Parse(guessCaps()); err == nil {
		t.Fatal("expected a parse error")
	} else if strings.Contains(err.Error(), "panic") {
		t.Fatalf("panic: %v", err)
	}
}
