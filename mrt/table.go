package mrt

import (
	"net/netip"
	"time"

	"github.com/bgpfix/bgpfix/nlri"
)

// TABLE_DUMP_V2 subtypes, see https://www.iana.org/assignments/mrt/mrt.xhtml
// NB: kept out of the Sub enumer set - the values overlap BGP4MP subtypes
const (
	PEER_INDEX_TABLE   Sub = 1
	RIB_IPV4_UNICAST   Sub = 2
	RIB_IPV4_MULTICAST Sub = 3
	RIB_IPV6_UNICAST   Sub = 4
	RIB_IPV6_MULTICAST Sub = 5
	RIB_GENERIC        Sub = 6
)

// legacy TABLE_DUMP (v1) subtypes = AFI values
const (
	TD_IPV4 Sub = 1
	TD_IPV6 Sub = 2
)

// PeerEntry describes one peer from a PEER_INDEX_TABLE (or a v1 record).
type PeerEntry struct {
	BgpId netip.Addr // peer BGP identifier
	IP    netip.Addr // peer IP address
	AS    uint32     // peer AS number
}

// RibEntry describes one RIB entry: a route to the parent Table.Prefix.
type RibEntry struct {
	PeerIndex  uint16    // index into the peer table
	Originated time.Time // when the route was received
	Attrs      []byte    // raw BGP path attributes, referencing Mrt.Data
}

// Table represents an MRT TABLE_DUMP (v1) or TABLE_DUMP_V2 record (rfc6396/4.2-4.3).
// Read-only: only parsing MRT dumps is supported.
type Table struct {
	Mrt *Mrt // parent MRT message

	// PEER_INDEX_TABLE
	CollectorId netip.Addr  // collector BGP identifier
	ViewName    string      // optional view name
	Peers       []PeerEntry // peer table, referencing Mrt.Data

	// RIB_* records (v1 records give exactly 1 entry + 1 peer)
	Seq     uint32      // record sequence number
	Prefix  nlri.Prefix // the prefix this record describes
	Entries []RibEntry  // routes to Prefix, referencing Mrt.Data
}

// Init initializes t to use parent mrt
func (t *Table) Init(mrt *Mrt) {
	t.Mrt = mrt
}

// Reset prepares t for re-use
func (t *Table) Reset() {
	t.CollectorId = netip.Addr{}
	t.ViewName = ""
	t.Peers = t.Peers[:0]
	t.Seq = 0
	t.Prefix = nlri.Prefix{}
	t.Entries = t.Entries[:0]
}

// Parse parses t.Mrt as a TABLE_DUMP / TABLE_DUMP_V2 record, referencing data.
// Unsupported subtypes (multicast, RIB_GENERIC, ADD_PATH) return ErrSub.
func (t *Table) Parse() error {
	t.Reset()
	mrt := t.Mrt
	buf := mrt.Data

	switch mrt.Type {
	case TABLE_DUMP2:
		switch mrt.Sub {
		case PEER_INDEX_TABLE:
			return t.parsePeerIndex(buf)
		case RIB_IPV4_UNICAST:
			return t.parseRib(buf, false)
		case RIB_IPV6_UNICAST:
			return t.parseRib(buf, true)
		default:
			return ErrSub
		}
	case TABLE_DUMP:
		switch mrt.Sub {
		case TD_IPV4:
			return t.parseV1(buf, false)
		case TD_IPV6:
			return t.parseV1(buf, true)
		default:
			return ErrSub
		}
	default:
		return ErrType
	}
}

// parsePeerIndex parses a PEER_INDEX_TABLE record (rfc6396/4.3.1)
func (t *Table) parsePeerIndex(buf []byte) error {
	if len(buf) < 8 {
		return ErrShort
	}

	// collector BGP ID + view name
	t.CollectorId = netip.AddrFrom4([4]byte(buf[0:4]))
	vlen := int(msb.Uint16(buf[4:6]))
	buf = buf[6:]
	if len(buf) < vlen+2 {
		return ErrShort
	}
	t.ViewName = string(buf[:vlen])
	buf = buf[vlen:]

	// peer entries
	count := int(msb.Uint16(buf[0:2]))
	buf = buf[2:]
	for range count {
		if len(buf) < 1+4 {
			return ErrShort
		}
		ptype := buf[0]
		var pe PeerEntry
		pe.BgpId = netip.AddrFrom4([4]byte(buf[1:5]))
		buf = buf[5:]

		// peer IP: bit 0 selects IPv6
		if ptype&0b01 != 0 {
			if len(buf) < 16 {
				return ErrShort
			}
			pe.IP = netip.AddrFrom16([16]byte(buf[0:16]))
			buf = buf[16:]
		} else {
			if len(buf) < 4 {
				return ErrShort
			}
			pe.IP = netip.AddrFrom4([4]byte(buf[0:4]))
			buf = buf[4:]
		}

		// peer AS: bit 1 selects 4 bytes
		if ptype&0b10 != 0 {
			if len(buf) < 4 {
				return ErrShort
			}
			pe.AS = msb.Uint32(buf[0:4])
			buf = buf[4:]
		} else {
			if len(buf) < 2 {
				return ErrShort
			}
			pe.AS = uint32(msb.Uint16(buf[0:2]))
			buf = buf[2:]
		}

		t.Peers = append(t.Peers, pe)
	}

	return nil
}

// parseRib parses a RIB_IPV4_UNICAST / RIB_IPV6_UNICAST record (rfc6396/4.3.2)
func (t *Table) parseRib(buf []byte, ipv6 bool) error {
	if len(buf) < 4+1 {
		return ErrShort
	}

	// sequence number + prefix
	t.Seq = msb.Uint32(buf[0:4])
	buf = buf[4:]
	var err error
	buf, err = t.parsePrefix(buf, ipv6)
	if err != nil {
		return err
	}

	// rib entries
	if len(buf) < 2 {
		return ErrShort
	}
	count := int(msb.Uint16(buf[0:2]))
	buf = buf[2:]
	for range count {
		if len(buf) < 2+4+2 {
			return ErrShort
		}
		var re RibEntry
		re.PeerIndex = msb.Uint16(buf[0:2])
		re.Originated = time.Unix(int64(msb.Uint32(buf[2:6])), 0).UTC()
		alen := int(msb.Uint16(buf[6:8]))
		buf = buf[8:]
		if len(buf) < alen {
			return ErrShort
		}
		re.Attrs = buf[:alen]
		buf = buf[alen:]

		t.Entries = append(t.Entries, re)
	}

	return nil
}

// parseV1 parses a legacy TABLE_DUMP record (rfc6396/4.2)
// into a single synthetic peer + entry, sharing the v2 emission path.
func (t *Table) parseV1(buf []byte, ipv6 bool) error {
	iplen := 4
	if ipv6 {
		iplen = 16
	}

	// view + seq + prefix + prefix len + status + originated
	if len(buf) < 2+2+iplen+1+1+4 {
		return ErrShort
	}
	t.Seq = uint32(msb.Uint16(buf[2:4]))
	addr, _ := netip.AddrFromSlice(buf[4 : 4+iplen])
	bits := int(buf[4+iplen])
	// NB: buf[4+iplen+1] is the status octet, unused
	originated := time.Unix(int64(msb.Uint32(buf[4+iplen+2:])), 0).UTC()
	buf = buf[4+iplen+2+4:]
	if bits > addr.BitLen() {
		return ErrLength
	}
	pfx, _ := addr.Prefix(bits)
	t.Prefix = nlri.FromPrefix(pfx)

	// peer IP + peer AS + attributes
	if len(buf) < iplen+2+2 {
		return ErrShort
	}
	peer, _ := netip.AddrFromSlice(buf[0:iplen])
	var pe PeerEntry
	pe.IP = peer
	pe.AS = uint32(msb.Uint16(buf[iplen : iplen+2]))
	alen := int(msb.Uint16(buf[iplen+2 : iplen+4]))
	buf = buf[iplen+4:]
	if len(buf) < alen {
		return ErrShort
	}

	t.Peers = append(t.Peers, pe)
	t.Entries = append(t.Entries, RibEntry{
		PeerIndex:  0,
		Originated: originated,
		Attrs:      buf[:alen],
	})

	return nil
}

// parsePrefix reads a length-prefixed NLRI prefix into t.Prefix
func (t *Table) parsePrefix(buf []byte, ipv6 bool) ([]byte, error) {
	bits := int(buf[0])
	blen := (bits + 7) / 8
	buf = buf[1:]
	if len(buf) < blen {
		return nil, ErrShort
	}

	// right-pad prefix bytes to a full address
	var addr netip.Addr
	if ipv6 {
		if bits > 128 {
			return nil, ErrLength
		}
		var a16 [16]byte
		copy(a16[:], buf[:blen])
		addr = netip.AddrFrom16(a16)
	} else {
		if bits > 32 {
			return nil, ErrLength
		}
		var a4 [4]byte
		copy(a4[:], buf[:blen])
		addr = netip.AddrFrom4(a4)
	}

	pfx, _ := addr.Prefix(bits)
	t.Prefix = nlri.FromPrefix(pfx)
	return buf[blen:], nil
}
