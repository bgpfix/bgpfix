package rpki

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/netip"
	"time"
)

// CCR (Canonical Cache Representation, draft-ietf-sidrops-rpki-ccr) is a DER
// snapshot of a validated RPKI cache, written by rpki-client and archived by
// RPKIviews. Only the VRP and ASPA (VAP) aspects are read here; the manifest,
// trust anchor and router key aspects are skipped, as are unknown ones.

var (
	oidCCR    = []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x01, 0x36} // 1.2.840.113549.1.9.16.1.54
	oidSHA256 = []byte{0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01}             // 2.16.840.1.101.3.4.2.1
)

// DER tags used by CCR (all single-byte)
const (
	derInteger     = 0x02
	derBitString   = 0x03
	derOctetString = 0x04
	derOID         = 0x06
	derGenTime     = 0x18
	derSequence    = 0x30

	ccrTagVersion = 0xa0 // [0] EXPLICIT INTEGER
	ccrTagVRPs    = 0xa2 // [2] EXPLICIT ROAPayloadState
	ccrTagVAPs    = 0xa3 // [3] EXPLICIT ASPAPayloadState
)

// CCRInfo describes a CCR file read by ReadCCR.
type CCRInfo struct {
	Version    int       // format version, always 0 for now
	ProducedAt time.Time // when the cache state was finalized
	HasVRPs    bool      // the file has the VRP aspect
	HasVAPs    bool      // the file has the ASPA aspect
	VRPs       int       // number of VRPs (prefix, maxLength, ASN tuples)
	VAPs       int       // number of ASPA records (customers)
}

var errDER = errors.New("malformed DER")

// derRead reads one TLV from b. Only single-byte tags and definite lengths
// are supported, which is all CCR needs.
func derRead(b []byte) (tag byte, val, rest []byte, err error) {
	if len(b) < 2 {
		return 0, nil, nil, fmt.Errorf("%w: truncated header", errDER)
	}
	tag = b[0]
	if tag&0x1f == 0x1f {
		return 0, nil, nil, fmt.Errorf("%w: multi-byte tag", errDER)
	}

	n, off := uint64(b[1]), 2
	if n >= 0x80 {
		k := int(n & 0x7f)
		if k == 0 || k > 4 || len(b) < 2+k {
			return 0, nil, nil, fmt.Errorf("%w: bad length", errDER)
		}
		n = 0
		for _, x := range b[2 : 2+k] {
			n = n<<8 | uint64(x)
		}
		off += k
	}
	// NB: uint64, so that a 4-byte length cannot wrap negative on 32-bit
	if n > uint64(len(b)-off) {
		return 0, nil, nil, fmt.Errorf("%w: length %d exceeds data", errDER, n)
	}
	end := off + int(n)
	return tag, b[off:end], b[end:], nil
}

// derExpect reads one TLV that must have the given tag.
func derExpect(b []byte, want byte) (val, rest []byte, err error) {
	tag, val, rest, err := derRead(b)
	if err != nil {
		return nil, nil, err
	}
	if tag != want {
		return nil, nil, fmt.Errorf("%w: tag 0x%02x, want 0x%02x", errDER, tag, want)
	}
	return val, rest, nil
}

// derOnly is like derExpect, but the TLV must span all of b.
func derOnly(b []byte, want byte) ([]byte, error) {
	val, rest, err := derExpect(b, want)
	if err == nil && len(rest) != 0 {
		err = fmt.Errorf("%w: %d trailing bytes", errDER, len(rest))
	}
	return val, err
}

// derUint32 parses a non-negative INTEGER value that fits in 32 bits.
func derUint32(v []byte) (uint32, error) {
	if len(v) == 0 || v[0]&0x80 != 0 {
		return 0, fmt.Errorf("%w: bad INTEGER", errDER)
	}
	if len(v) > 1 && v[0] == 0 {
		v = v[1:]
	}
	if len(v) > 4 {
		return 0, fmt.Errorf("%w: INTEGER out of range", errDER)
	}
	var n uint32
	for _, x := range v {
		n = n<<8 | uint32(x)
	}
	return n, nil
}

// derNext reads the next TLV and returns its full encoding (tag and length included) too.
func derNext(b []byte, want byte) (val, full, rest []byte, err error) {
	val, rest, err = derExpect(b, want)
	if err != nil {
		return nil, nil, nil, err
	}
	return val, b[:len(b)-len(rest)], rest, nil
}

// isCCR returns true iff data looks like a CCR file: a DER SEQUENCE
// starting with the CCR content type OID.
func isCCR(data []byte) bool {
	tag, val, _, err := derRead(data)
	if err != nil || tag != derSequence {
		return false
	}
	tag, oid, _, err := derRead(val)
	return err == nil && tag == derOID && bytes.Equal(oid, oidCCR)
}

// ReadCCR parses the CCR file in data. For each VRP in the file it calls
// onVRP, and for each ASPA record onASPA; either may be nil. The providers
// slice passed to onASPA is reused: copy it to keep it.
//
// The integrity hash of each aspect is verified, and every field is bounds
// checked; on any failure it stops and returns an error (callbacks may have
// already been called for the preceding records, discard such partial state).
func ReadCCR(data []byte, onVRP func(p netip.Prefix, maxLen uint8, asn uint32), onASPA func(cas uint32, providers []uint32)) (info CCRInfo, err error) {
	// ContentInfo ::= SEQUENCE { contentType OID, content [0] EXPLICIT ... }
	ci, err := derOnly(data, derSequence)
	if err != nil {
		return info, fmt.Errorf("ContentInfo: %w", err)
	}
	oid, ci, err := derExpect(ci, derOID)
	if err != nil {
		return info, fmt.Errorf("contentType: %w", err)
	}
	if !bytes.Equal(oid, oidCCR) {
		return info, errors.New("not a CCR: unexpected contentType")
	}
	ci, err = derOnly(ci, 0xa0)
	if err != nil {
		return info, fmt.Errorf("content: %w", err)
	}
	body, err := derOnly(ci, derSequence)
	if err != nil {
		return info, fmt.Errorf("RpkiCanonicalCacheRepresentation: %w", err)
	}

	// version [0] INTEGER DEFAULT 0
	if len(body) > 0 && body[0] == ccrTagVersion {
		v, rest, err := derExpect(body, ccrTagVersion)
		if err != nil {
			return info, fmt.Errorf("version: %w", err)
		}
		iv, err := derOnly(v, derInteger)
		if err != nil {
			return info, fmt.Errorf("version: %w", err)
		}
		ver, err := derUint32(iv)
		if err != nil {
			return info, fmt.Errorf("version: %w", err)
		}
		if ver != 0 {
			return info, fmt.Errorf("unsupported CCR version %d", ver)
		}
		info.Version, body = int(ver), rest
	}

	// hashAlg: AlgorithmIdentifier with SHA-256 and no parameters
	alg, body, err := derExpect(body, derSequence)
	if err != nil {
		return info, fmt.Errorf("hashAlg: %w", err)
	}
	if oid, rest, err := derExpect(alg, derOID); err != nil || len(rest) != 0 || !bytes.Equal(oid, oidSHA256) {
		return info, errors.New("hashAlg is not SHA-256")
	}

	// producedAt GeneralizedTime
	ts, body, err := derExpect(body, derGenTime)
	if err != nil {
		return info, fmt.Errorf("producedAt: %w", err)
	}
	if info.ProducedAt, err = time.Parse("20060102150405Z", string(ts)); err != nil {
		return info, fmt.Errorf("producedAt: %w", err)
	}

	// state aspects, each wrapped in an EXPLICIT context tag; skip the others
	if len(body) == 0 {
		return info, errors.New("no state aspects")
	}
	for len(body) > 0 {
		var tag byte
		var val []byte
		tag, val, body, err = derRead(body)
		if err != nil {
			return info, fmt.Errorf("aspect: %w", err)
		}
		switch tag {
		case ccrTagVRPs:
			info.HasVRPs = true
			info.VRPs, err = readCCRVRPs(val, onVRP)
			if err != nil {
				return info, fmt.Errorf("vrps: %w", err)
			}
		case ccrTagVAPs:
			info.HasVAPs = true
			info.VAPs, err = readCCRVAPs(val, onASPA)
			if err != nil {
				return info, fmt.Errorf("vaps: %w", err)
			}
		}
	}
	return info, nil
}

// readCCRState splits an aspect into its payload sequence (the DER whose hash is
// stored in the aspect) and verifies the hash. Returns the sequence content.
func readCCRState(val []byte) ([]byte, error) {
	st, err := derOnly(val, derSequence)
	if err != nil {
		return nil, err
	}
	items, full, st, err := derNext(st, derSequence)
	if err != nil {
		return nil, err
	}
	hash, err := derOnly(st, derOctetString)
	if err != nil {
		return nil, err
	}
	if sum := sha256.Sum256(full); !bytes.Equal(hash, sum[:]) {
		return nil, errors.New("integrity hash mismatch")
	}
	return items, nil
}

func readCCRVRPs(val []byte, onVRP func(netip.Prefix, uint8, uint32)) (n int, err error) {
	items, err := readCCRState(val)
	if err != nil {
		return 0, err
	}

	for len(items) > 0 {
		// ROAPayloadSet ::= SEQUENCE { asID ASID, ipAddrBlocks SEQUENCE OF ROAIPAddressFamily }
		var set []byte
		set, items, err = derExpect(items, derSequence)
		if err != nil {
			return n, err
		}
		v, set, err := derExpect(set, derInteger)
		if err != nil {
			return n, err
		}
		asn, err := derUint32(v)
		if err != nil {
			return n, err
		}
		blocks, err := derOnly(set, derSequence)
		if err != nil {
			return n, err
		}

		// ipAddrBlocks ::= SEQUENCE (SIZE(1..2)) OF ROAIPAddressFamily
		if len(blocks) == 0 {
			return n, fmt.Errorf("%w: empty ipAddrBlocks", errDER)
		}
		for nfam := 0; len(blocks) > 0; nfam++ {
			if nfam == 2 {
				return n, fmt.Errorf("%w: too many ipAddrBlocks", errDER)
			}
			// ROAIPAddressFamily ::= SEQUENCE { addressFamily OCTET STRING (SIZE(2)), addresses SEQUENCE OF ROAIPAddress }
			var fam []byte
			fam, blocks, err = derExpect(blocks, derSequence)
			if err != nil {
				return n, err
			}
			afi, fam, err := derExpect(fam, derOctetString)
			if err != nil {
				return n, err
			}
			var size int // address size in bytes
			switch {
			case len(afi) == 2 && afi[0] == 0 && afi[1] == 1:
				size = 4
			case len(afi) == 2 && afi[0] == 0 && afi[1] == 2:
				size = 16
			default:
				return n, fmt.Errorf("unsupported addressFamily %x", afi)
			}
			addrs, err := derOnly(fam, derSequence)
			if err != nil {
				return n, err
			}

			for len(addrs) > 0 {
				// ROAIPAddress ::= SEQUENCE { address BIT STRING, maxLength INTEGER OPTIONAL }
				var ent []byte
				ent, addrs, err = derExpect(addrs, derSequence)
				if err != nil {
					return n, err
				}
				bs, ent, err := derExpect(ent, derBitString)
				if err != nil {
					return n, err
				}
				if len(bs) == 0 || bs[0] > 7 || len(bs)-1 > size || (len(bs) == 1 && bs[0] != 0) {
					return n, fmt.Errorf("%w: bad address BIT STRING", errDER)
				}
				if len(bs) > 1 && bs[len(bs)-1]&(1<<bs[0]-1) != 0 {
					return n, fmt.Errorf("%w: nonzero BIT STRING padding", errDER)
				}
				bits := (len(bs)-1)*8 - int(bs[0])

				maxLen := bits
				if len(ent) > 0 {
					v, rest, err := derExpect(ent, derInteger)
					if err != nil || len(rest) != 0 {
						return n, fmt.Errorf("%w: bad maxLength", errDER)
					}
					ml, err := derUint32(v)
					if err != nil || int(ml) < bits || int(ml) > size*8 {
						return n, fmt.Errorf("maxLength out of range for /%d", bits)
					}
					maxLen = int(ml)
				}

				if onVRP != nil {
					var a [16]byte
					copy(a[:], bs[1:])
					var addr netip.Addr
					if size == 4 {
						addr = netip.AddrFrom4([4]byte(a[:4]))
					} else {
						addr = netip.AddrFrom16(a)
					}
					onVRP(netip.PrefixFrom(addr, bits), uint8(maxLen), asn)
				}
				n++
			}
		}
	}
	return n, nil
}

func readCCRVAPs(val []byte, onASPA func(uint32, []uint32)) (n int, err error) {
	items, err := readCCRState(val)
	if err != nil {
		return 0, err
	}

	var provs []uint32
	for len(items) > 0 {
		// ASPAPayloadSet ::= SEQUENCE { customerASID CAS, providers SEQUENCE OF PAS }
		var set []byte
		set, items, err = derExpect(items, derSequence)
		if err != nil {
			return n, err
		}
		v, set, err := derExpect(set, derInteger)
		if err != nil {
			return n, err
		}
		cas, err := derUint32(v)
		if err != nil {
			return n, err
		}
		list, err := derOnly(set, derSequence)
		if err != nil {
			return n, err
		}

		provs = provs[:0]
		for len(list) > 0 {
			v, rest, err := derExpect(list, derInteger)
			if err != nil {
				return n, err
			}
			pas, err := derUint32(v)
			if err != nil {
				return n, err
			}
			provs, list = append(provs, pas), rest
		}
		if len(provs) == 0 {
			return n, fmt.Errorf("%w: ASPA of AS%d has no providers", errDER, cas)
		}

		if onASPA != nil {
			onASPA(cas, provs)
		}
		n++
	}
	return n, nil
}

// ParseCCR parses a CCR file (see ReadCCR) into the pending set; call Apply to
// publish. Unlike ParseJSON, it is strict: any malformed or inconsistent field
// fails the whole file, so the caller should Flush the pending set on error.
func (c *Cache) ParseCCR(data []byte) (CCRInfo, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	return ReadCCR(data,
		func(p netip.Prefix, maxLen uint8, asn uint32) { c.addVRP(true, p, maxLen, asn) },
		func(cas uint32, providers []uint32) { c.addASPA(true, cas, providers) })
}
