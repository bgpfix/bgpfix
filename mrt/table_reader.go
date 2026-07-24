package mrt

import (
	"bytes"
	"maps"
	"net/netip"
	"slices"
	"strconv"

	"github.com/bgpfix/bgpfix/afi"
	"github.com/bgpfix/bgpfix/attrs"
	"github.com/bgpfix/bgpfix/msg"
	"github.com/bgpfix/bgpfix/nlri"
	"github.com/bgpfix/bgpfix/pipe"
)

// flush the pending UPDATE when its estimated size reaches this limit,
// so that marshaled messages stay under the 4KiB BGP message limit
const tablePendingMax = 3800

// tablePending is an under-construction UPDATE aggregating
// consecutive same-attribute prefixes for one peer
type tablePending struct {
	m    *msg.Msg // the UPDATE being built
	key  []byte   // owned attr blob, MP_REACH excised (aggregation key)
	nh   []byte   // owned next-hop bytes from the excised MP_REACH
	size int      // estimated marshaled message size
}

// v1peer identifies a legacy TABLE_DUMP peer, given inline in each record
type v1peer struct {
	ip netip.Addr
	as uint32
}

// tableState is the mutable Reader state for table dump records
type tableState struct {
	peers   []PeerEntry              // owned copy of the last PEER_INDEX_TABLE
	pending map[uint16]*tablePending // per-peer pending UPDATE
	v1index map[v1peer]uint16        // v1 peer -> synthetic index into peers
}

// emitTable converts the just-parsed table dump record in br.mrt
// into BGP UPDATE messages, aggregating consecutive same-attribute
// prefixes per peer. cb may be nil.
func (br *Reader) emitTable(cb pipe.CallbackFunc) error {
	var (
		mrt = br.mrt
		t   = &mrt.Table
		ts  = &br.table
	)

	if ts.pending == nil {
		ts.pending = make(map[uint16]*tablePending)
	}

	// a new peer index table starts a new RIB: flush and (re)load peers
	if mrt.Type == TABLE_DUMP2 && mrt.Sub == PEER_INDEX_TABLE {
		if err := br.Flush(cb); err != nil {
			return err
		}
		ts.peers = append(ts.peers[:0], t.Peers...)
		return nil
	}

	// v1 records carry their peer inline: translate to a synthetic index
	var v1fix uint16
	if mrt.Type == TABLE_DUMP {
		if ts.v1index == nil {
			ts.v1index = make(map[v1peer]uint16)
		}
		pe := t.Peers[0]
		key := v1peer{pe.IP, pe.AS}
		idx, ok := ts.v1index[key]
		if !ok {
			idx = uint16(len(ts.peers))
			ts.v1index[key] = idx
			ts.peers = append(ts.peers, pe)
		}
		v1fix = idx
	}

	// process the RIB entries
	for i := range t.Entries {
		e := &t.Entries[i]

		// resolve the peer
		idx := e.PeerIndex
		if mrt.Type == TABLE_DUMP {
			idx = v1fix
		}
		if int(idx) >= len(ts.peers) {
			br.Stats.Garbled++
			continue // no peer index table?
		}

		// split the attr blob; for v2, excise the MP_REACH attribute
		// NB: ats and nh reference mrt.Data (or a fresh slice)
		ats, nh := e.Attrs, []byte(nil)
		if mrt.Type == TABLE_DUMP2 {
			var err error
			ats, nh, err = tableAttrs(e.Attrs)
			if err != nil {
				br.Stats.Garbled++
				continue
			}
		}

		// can we bundle into the pending UPDATE?
		pend := ts.pending[idx]
		if pend != nil {
			psize := prefixWireLen(t.Prefix)
			if bytes.Equal(pend.key, ats) && bytes.Equal(pend.nh, nh) &&
				pend.size+psize <= tablePendingMax {
				pend.m.Update.AddReach(t.Prefix)
				pend.size += psize
				br.Stats.Bundled++
				continue
			}

			// no: flush it downstream
			delete(ts.pending, idx)
			if err := br.flushPending(pend, cb); err != nil {
				return err
			}
		}

		// start a new pending UPDATE
		pend, err := br.newPending(ats, nh, &ts.peers[idx])
		if err != nil {
			br.Stats.Garbled++
			continue
		}
		ts.pending[idx] = pend
	}

	return nil
}

// newPending starts a new pending UPDATE for a RIB entry from peer pe,
// given its already-split attributes ats and next-hop bytes nh (borrowed).
// Returns nil error iff the entry attributes parsed OK.
func (br *Reader) newPending(ats, nh []byte, pe *PeerEntry) (*tablePending, error) {
	mrt := br.mrt

	// own the borrowed slices, they must outlive mrt.Data
	ats, nh = bytes.Clone(ats), bytes.Clone(nh)

	// synthesize the UPDATE
	m := br.pipe.GetMsg()
	m.Time = mrt.Time
	u := &m.Switch(msg.UPDATE).Update

	// table dump attribute encoding: v2 always AS4, v1 never
	if mrt.Type == TABLE_DUMP2 {
		m.ParseAS4 = 1
	} else {
		m.ParseAS4 = -1
	}
	m.ParseAddPath = -1

	// parse the attributes
	u.AttrsRaw = ats
	if err := u.ParseAttrs(br.pipe.Caps); err != nil {
		br.pipe.PutMsg(m)
		return nil, err
	}

	// next hop from the excised MP_REACH?
	switch len(nh) {
	case 0: // none, use ATTR_NEXTHOP from the blob
	case 4: // IPv4
		a := u.Attrs.Use(attrs.ATTR_NEXTHOP).(*attrs.IP)
		a.Addr = netip.AddrFrom4([4]byte(nh))
	default: // IPv6 (+ optional link-local)
		addr, ll, ok := attrs.ParseNH(nh)
		if !ok {
			br.pipe.PutMsg(m)
			return nil, ErrLength
		}
		mpr := u.Attrs.Use(attrs.ATTR_MP_REACH).(*attrs.MP)
		mpr.AS = afi.AS_IPV6_UNICAST
		mpp := attrs.NewMPPrefixes(mpr).(*attrs.MPPrefixes)
		mpp.NextHop = addr
		mpp.LinkLocal = ll
		mpr.Value = mpp
	}

	// announce the prefix
	u.AddReach(mrt.Table.Prefix)

	// tag with peer metadata
	if !br.NoTags {
		tags := pipe.UseContext(m).UseTags()
		tags["PEER_AS"] = strconv.FormatUint(uint64(pe.AS), 10)
		tags["PEER_IP"] = pe.IP.String()
	}

	return &tablePending{
		m:    m,
		key:  ats,
		nh:   nh,
		size: msg.HEADLEN + 4 + len(ats) + 64 + prefixWireLen(mrt.Table.Prefix),
	}, nil
}

// flushPending emits one pending UPDATE downstream. cb may be nil.
func (br *Reader) flushPending(pend *tablePending, cb pipe.CallbackFunc) error {
	m := pend.m
	if cb != nil && !cb(m) {
		br.pipe.PutMsg(m)
		return nil // silent skip
	}
	return br.in.WriteMsg(m)
}

// Flush emits all pending aggregated UPDATEs (table dump reads).
// Call when the input stream ends. Does nothing for BGP4MP streams.
// cb may be nil, see WriteFunc.
func (br *Reader) Flush(cb pipe.CallbackFunc) error {
	ts := &br.table
	if len(ts.pending) == 0 {
		return nil
	}

	// deterministic order: by peer index
	for _, idx := range slices.Sorted(maps.Keys(ts.pending)) {
		pend := ts.pending[idx]
		delete(ts.pending, idx)
		if err := br.flushPending(pend, cb); err != nil {
			return err
		}
	}
	return nil
}

// tableAttrs splits a TABLE_DUMP_V2 attribute blob: returns the blob with
// the MP_REACH attribute (if any) excised, plus its truncated next-hop bytes
// (rfc6396/4.3.4: RIB entry MP_REACH is just next-hop length + next-hop).
// Returns ats referencing (or equal to) blob; nh references blob.
func tableAttrs(blob []byte) (ats, nh []byte, err error) {
	for i := 0; i < len(blob); {
		if len(blob)-i < 3 {
			return nil, nil, ErrLength
		}

		// parse attribute type and length
		cf := attrs.CodeFlags(msb.Uint16(blob[i : i+2]))
		hdr, alen := 3, int(blob[i+2])
		if cf.HasFlags(attrs.ATTR_EXTENDED) {
			if len(blob)-i < 4 {
				return nil, nil, ErrLength
			}
			hdr, alen = 4, int(msb.Uint16(blob[i+2:i+4]))
		}
		if len(blob)-i < hdr+alen {
			return nil, nil, ErrLength
		}

		// excise MP_REACH, keep everything else
		if cf.Code() == attrs.ATTR_MP_REACH {
			body := blob[i+hdr : i+hdr+alen]
			switch {
			case len(body) >= 1 && int(body[0]) == len(body)-1:
				// truncated rfc6396/4.3.4 form: next-hop length + next-hop
				nh = body[1:]
			case len(body) >= 5 && 4+int(body[3]) <= len(body):
				// full rfc4760 form, as written by RouteViews;
				// the embedded NLRI repeats the record prefix - ignored
				nh = body[4 : 4+body[3]]
			default:
				return nil, nil, ErrLength
			}
			ats = append(blob[:i:i], blob[i+hdr+alen:]...)
			return ats, nh, nil
		}

		i += hdr + alen
	}

	// no MP_REACH: the blob is ready as-is
	return blob, nil, nil
}

// prefixWireLen estimates the marshaled NLRI size of prefix p
func prefixWireLen(p nlri.Prefix) int {
	return 1 + (p.Bits()+7)/8
}
