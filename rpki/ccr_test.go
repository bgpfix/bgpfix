package rpki

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"
)

// DER encoding helpers for building test CCRs

func tlv(tag byte, parts ...[]byte) []byte {
	c := bytes.Join(parts, nil)
	n := len(c)
	if n < 0x80 {
		return append([]byte{tag, byte(n)}, c...)
	}
	var l []byte
	for ; n > 0; n >>= 8 {
		l = append([]byte{byte(n)}, l...)
	}
	return append(append([]byte{tag, 0x80 | byte(len(l))}, l...), c...)
}

func derInt(v uint32) []byte {
	b := []byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
	for len(b) > 1 && b[0] == 0 {
		b = b[1:]
	}
	if b[0]&0x80 != 0 {
		b = append([]byte{0}, b...)
	}
	return tlv(derInteger, b)
}

type testROA struct {
	prefix string
	maxLen int
	asn    uint32
}

func roaAddr(p netip.Prefix, maxLen int) []byte {
	n := (p.Bits() + 7) / 8
	bs := append([]byte{byte(n*8 - p.Bits())}, p.Masked().Addr().AsSlice()[:n]...)
	if maxLen == p.Bits() {
		return tlv(derSequence, tlv(derBitString, bs))
	}
	return tlv(derSequence, tlv(derBitString, bs), derInt(uint32(maxLen)))
}

// testState wraps a payload sequence in its aspect: [tag] SEQUENCE { items, hash }
func testState(tag byte, items []byte) []byte {
	sum := sha256.Sum256(items)
	return tlv(tag, tlv(derSequence, items, tlv(derOctetString, sum[:])))
}

func testVRPs(roas []testROA) []byte {
	var sets []byte
	for _, asn := range []uint32{64496, 64497, 4200000000} { // ascending asID
		fams := map[byte][]byte{}
		for _, r := range roas {
			if r.asn != asn {
				continue
			}
			p := netip.MustParsePrefix(r.prefix)
			afi := byte(1)
			if p.Addr().Is6() {
				afi = 2
			}
			fams[afi] = append(fams[afi], roaAddr(p, r.maxLen)...)
		}
		var blocks []byte
		for _, afi := range []byte{1, 2} {
			if a := fams[afi]; a != nil {
				blocks = append(blocks, tlv(derSequence, tlv(derOctetString, []byte{0, afi}), tlv(derSequence, a))...)
			}
		}
		if blocks != nil {
			sets = append(sets, tlv(derSequence, derInt(asn), tlv(derSequence, blocks))...)
		}
	}
	return testState(ccrTagVRPs, tlv(derSequence, sets))
}

func testVAPs(vaps map[uint32][]uint32) []byte {
	var sets []byte
	for _, cas := range []uint32{64496, 64497} { // ascending customerASID
		if provs, ok := vaps[cas]; ok {
			var l []byte
			for _, p := range provs {
				l = append(l, derInt(p)...)
			}
			sets = append(sets, tlv(derSequence, derInt(cas), tlv(derSequence, l))...)
		}
	}
	return testState(ccrTagVAPs, tlv(derSequence, sets))
}

var (
	testAlg = tlv(derSequence, tlv(derOID, oidSHA256))
	testTS  = tlv(derGenTime, []byte("20261025000753Z"))
)

func testCCR(aspects ...[]byte) []byte {
	body := tlv(derSequence, append([][]byte{testAlg, testTS}, aspects...)...)
	return tlv(derSequence, tlv(derOID, oidCCR), tlv(0xa0, body))
}

func testSample() []byte {
	return testCCR(
		testVRPs([]testROA{
			{"192.0.2.0/24", 24, 64496},
			{"198.51.100.0/22", 24, 64496},
			{"203.0.113.0/24", 25, 64497},
			{"2001:db8::/32", 48, 64496},
			{"0.0.0.0/0", 0, 4200000000},
			{"2001:db8:1234::/48", 48, 64497},
		}),
		testVAPs(map[uint32][]uint32{64496: {64497, 64498}, 64497: {0}}),
	)
}

func TestReadCCR(t *testing.T) {
	type vrp struct {
		p  string
		ml uint8
		as uint32
	}
	var vrps []vrp
	aspas := map[uint32][]uint32{}
	info, err := ReadCCR(testSample(),
		func(p netip.Prefix, ml uint8, as uint32) { vrps = append(vrps, vrp{p.String(), ml, as}) },
		func(cas uint32, provs []uint32) { aspas[cas] = slices.Clone(provs) })
	if err != nil {
		t.Fatal(err)
	}

	want := []vrp{
		{"192.0.2.0/24", 24, 64496}, {"198.51.100.0/22", 24, 64496}, {"2001:db8::/32", 48, 64496},
		{"203.0.113.0/24", 25, 64497}, {"2001:db8:1234::/48", 48, 64497}, {"0.0.0.0/0", 0, 4200000000},
	}
	if !slices.Equal(vrps, want) {
		t.Errorf("VRPs:\n got %v\nwant %v", vrps, want)
	}
	if !slices.Equal(aspas[64496], []uint32{64497, 64498}) || !slices.Equal(aspas[64497], []uint32{0}) || len(aspas) != 2 {
		t.Errorf("ASPAs: %v", aspas)
	}
	if info.VRPs != 6 || info.VAPs != 2 || !info.HasVRPs || !info.HasVAPs || info.Version != 0 {
		t.Errorf("info: %+v", info)
	}
	if !info.ProducedAt.Equal(time.Date(2026, 10, 25, 0, 7, 53, 0, time.UTC)) {
		t.Errorf("producedAt: %v", info.ProducedAt)
	}

	// only one aspect present is fine
	info, err = ReadCCR(testCCR(testVAPs(map[uint32][]uint32{64496: {64497}})), nil, nil)
	if err != nil || info.HasVRPs || !info.HasVAPs || info.VAPs != 1 {
		t.Errorf("VAPs only: %+v %v", info, err)
	}
}

func TestReadCCRRejects(t *testing.T) {
	good := testSample()
	if _, err := ReadCCR(good, nil, nil); err != nil {
		t.Fatal(err)
	}

	// integrity: flipping any byte of the aspects must be caught (by the hash or by the parser);
	// NB: producedAt carries no hash, so the header before the aspects is not covered
	for i := bytes.Index(good, testTS) + len(testTS); i < len(good); i++ {
		bad := slices.Clone(good)
		bad[i] ^= 0x01
		if _, err := ReadCCR(bad, nil, nil); err == nil {
			t.Fatalf("byte %d flipped, not detected", i)
		}
	}

	// truncation at every length must fail cleanly
	for n := 0; n < len(good); n++ {
		if _, err := ReadCCR(good[:n], nil, nil); err == nil {
			t.Fatalf("truncated to %d bytes, not detected", n)
		}
	}

	fam := tlv(derSequence, tlv(derOctetString, []byte{0, 1}), tlv(derSequence))
	rawVRPs := func(sets []byte) []byte { return testState(ccrTagVRPs, tlv(derSequence, sets)) }
	roa := func(r ...testROA) []byte { return testCCR(testVRPs(r)) }
	tests := map[string][]byte{
		"maxLength below prefix length": roa(testROA{"192.0.2.0/24", 23, 64496}),
		"maxLength above family limit":  roa(testROA{"192.0.2.0/24", 33, 64496}),
		"wrong content type":            bytes.Replace(good, oidCCR, append(slices.Clone(oidCCR[:10]), 0x37), 1),
		"hashAlg not SHA-256":           bytes.Replace(good, oidSHA256, append(slices.Clone(oidSHA256[:8]), 0x02), 1),
		"ASPA without providers":        testCCR(testVAPs(map[uint32][]uint32{64496: {}})),
		"version 1":                     tlv(derSequence, tlv(derOID, oidCCR), tlv(0xa0, tlv(derSequence, tlv(ccrTagVersion, derInt(1)), testAlg, testTS, testVAPs(map[uint32][]uint32{64496: {1}})))),
		"duplicate VRPs aspect":         testCCR(testVRPs(nil), testVRPs(nil)),
		"no aspects":                    testCCR(),
		"nonzero BIT STRING padding":    testCCR(rawVRPs(tlv(derSequence, derInt(64496), tlv(derSequence, tlv(derSequence, tlv(derOctetString, []byte{0, 1}), tlv(derSequence, tlv(derSequence, tlv(derBitString, []byte{7, 0x01})))))))),
		"trailing bytes":                append(slices.Clone(good), 0),
		"no ipAddrBlocks":               testCCR(rawVRPs(tlv(derSequence, derInt(64496), tlv(derSequence)))),
		"three ipAddrBlocks":            testCCR(rawVRPs(tlv(derSequence, derInt(64496), tlv(derSequence, fam, fam, fam)))),
		"unsupported address family":    bytes.Replace(roa(testROA{"192.0.2.0/24", 24, 64496}), []byte{0x04, 0x02, 0x00, 0x01}, []byte{0x04, 0x02, 0x00, 0x03}, 1),
	}
	for name, data := range tests {
		if _, err := ReadCCR(data, nil, nil); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestDERLengthOverflow(t *testing.T) {
	// NB: 4-byte length that would wrap negative as a 32-bit int
	if _, _, _, err := derRead([]byte{0x30, 0x84, 0xff, 0xff, 0xff, 0xff, 0x00}); err == nil {
		t.Error("accepted")
	}
}

func TestParseCCRFormats(t *testing.T) {
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	zw.Write(testSample())
	zw.Close()

	for name, data := range map[string][]byte{"ccr": testSample(), "ccr.gz": gz.Bytes()} {
		c := NewCache(nil)
		if err := c.Parse(data); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		c.Apply()
		v4, v6, as := c.Sizes()
		if v4 != 4 || v6 != 2 || as != 2 {
			t.Errorf("%s: sizes %d %d %d", name, v4, v6, as)
		}
		if got := c.ValidateOrigin(netip.MustParsePrefix("192.0.2.0/24"), 64496); got != ROV_VALID {
			t.Errorf("%s: ROV %d", name, got)
		}
		if got := c.ASPAs()[64496]; !slices.Equal(got, []uint32{64497, 64498}) {
			t.Errorf("%s: ASPA %v", name, got)
		}
	}

	// a CSV that starts with the byte 0x30 ('0') must still be CSV
	c := NewCache(nil)
	if err := c.Parse([]byte("0.0.0.0/0,24,AS64496\n")); err != nil {
		t.Fatalf("CSV starting with 0: %v", err)
	}
	if err := NewCache(nil).Parse([]byte(strings.Repeat("\x30", 8))); err == nil {
		t.Error("garbage accepted")
	}
}

func FuzzReadCCR(f *testing.F) {
	f.Add(testSample())
	f.Add(testCCR(testVAPs(map[uint32][]uint32{64496: {64497}})))
	f.Fuzz(func(t *testing.T, data []byte) {
		var vrps, aspas int
		info, err := ReadCCR(data,
			func(p netip.Prefix, ml uint8, as uint32) {
				if !p.IsValid() || int(ml) < p.Bits() || int(ml) > p.Addr().BitLen() {
					t.Fatalf("bad VRP %s maxLen %d", p, ml)
				}
				vrps++
			},
			func(cas uint32, provs []uint32) {
				if len(provs) == 0 {
					t.Fatal("ASPA without providers")
				}
				aspas++
			})
		if err == nil && (info.VRPs != vrps || info.VAPs != aspas) {
			t.Fatalf("counts: info %+v, callbacks %d/%d", info, vrps, aspas)
		}
		NewCache(nil).Parse(data) // must not panic either
	})
}
