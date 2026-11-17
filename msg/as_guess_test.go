package msg

import (
	"testing"

	"github.com/bgpfix/bgpfix/caps"
)

// a 2-byte AS_PATH that also parses as a valid 4-byte one must be read as 2-byte
func TestParseAS4GuessAmbiguous(t *testing.T) {
	ats := []byte{
		0x40, 1, 1, 0, // ORIGIN
		0x40, 2, 10, 2, 2, 0x84, 0xec, 0xec, 0x41, 1, 1, 0xb3, 0xb6, // [34028 60481] {46006}
		0x40, 3, 4, 10, 0, 0, 1, // NEXT_HOP
	}
	upd := []byte{0, 0, 0, byte(len(ats))}
	upd = append(upd, ats...)
	upd = append(upd, 24, 192, 0, 2)

	var cps caps.Caps
	cps.Use(caps.CAP_AS4)
	cps.Use(caps.CAP_AS_GUESS)

	m := NewMsg()
	m.Type = UPDATE
	m.Data = upd
	if err := m.Parse(cps); err != nil {
		t.Fatal(err)
	}
	if s := m.Update.AsPath().String(); s != "[34028,60481,[46006]]" {
		t.Errorf("AS_PATH = %s", s)
	}
	if m.ParseAS4 != -1 {
		t.Errorf("ParseAS4 = %d, want -1", m.ParseAS4)
	}
}

// a failed Parse must not leave the upper layer marked as parsed
func TestParseErrorResetsUpper(t *testing.T) {
	m := NewMsg()
	m.Type = UPDATE
	m.Data = []byte{0, 0, 0, 5, 0x40, 1, 2, 0, 0, 24, 192, 0, 2} // ORIGIN with length 2
	if m.Parse(caps.Caps{}) == nil {
		t.Fatal("expected a parse error")
	}
	if m.Upper != INVALID {
		t.Fatalf("Upper = %s after a failed Parse", m.Upper)
	}
	if m.Parse(caps.Caps{}) == nil {
		t.Fatal("expected a parse error again")
	}
}
