package meta

import (
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/bgpfix/bgpfix/json"
)

// Tags are message tags. The well-known ones, with ALL-CAPS keys, are typed fields;
// the others (lowercase by convention, eg. "rov/status") are kept sorted by key.
// Get and Set work for all keys. An empty value means no tag.
type Tags struct {
	PeerIP    netip.Addr // PEER_IP: BGP peer address
	PeerAS    uint32     // PEER_AS: BGP peer ASN
	PeerID    netip.Addr // PEER_ID: BGP peer identifier
	LocalIP   netip.Addr // LOCAL_IP: local address of the BGP session
	LocalAS   uint32     // LOCAL_AS: local ASN of the BGP session
	Collector string     // COLLECTOR: route collector name
	Router    string     // ROUTER: BMP router name or address
	Src       string     // SRC: source stage name

	Other []Tag // other tags, sorted by key
}

// Tag is a message tag
type Tag struct {
	Key, Val string
}

func tagCmp(t Tag, key string) int { return strings.Compare(t.Key, key) }

// Reset drops all tags
func (t *Tags) Reset() {
	other := t.Other[:0]
	*t = Tags{Other: other}
}

// Get returns the value of tag key, or "" if not set
func (t *Tags) Get(key string) string {
	if t == nil {
		return ""
	}
	switch key {
	case "PEER_IP":
		return addrString(t.PeerIP)
	case "PEER_AS":
		return asString(t.PeerAS)
	case "PEER_ID":
		return addrString(t.PeerID)
	case "LOCAL_IP":
		return addrString(t.LocalIP)
	case "LOCAL_AS":
		return asString(t.LocalAS)
	case "COLLECTOR":
		return t.Collector
	case "ROUTER":
		return t.Router
	case "SRC":
		return t.Src
	}
	if i, ok := slices.BinarySearchFunc(t.Other, key, tagCmp); ok {
		return t.Other[i].Val
	}
	return ""
}

// Set sets tag key to val; an empty or invalid val drops it
func (t *Tags) Set(key, val string) {
	switch key {
	case "PEER_IP":
		t.PeerIP, _ = netip.ParseAddr(val)
	case "PEER_AS":
		t.PeerAS = parseAS(val)
	case "PEER_ID":
		t.PeerID, _ = netip.ParseAddr(val)
	case "LOCAL_IP":
		t.LocalIP, _ = netip.ParseAddr(val)
	case "LOCAL_AS":
		t.LocalAS = parseAS(val)
	case "COLLECTOR":
		t.Collector = val
	case "ROUTER":
		t.Router = val
	case "SRC":
		t.Src = val
	default:
		i, ok := slices.BinarySearchFunc(t.Other, key, tagCmp)
		switch {
		case ok && val == "":
			t.Other = slices.Delete(t.Other, i, i+1)
		case ok:
			t.Other[i].Val = val
		case val != "":
			t.Other = slices.Insert(t.Other, i, Tag{key, val})
		}
	}
}

// Each calls cb for each tag with a value: the well-known ones first, then the others
func (t *Tags) Each(cb func(key, val string)) {
	if t == nil {
		return
	}
	for _, key := range [...]string{"COLLECTOR", "LOCAL_AS", "LOCAL_IP", "PEER_AS", "PEER_ID", "PEER_IP", "ROUTER", "SRC"} {
		if val := t.Get(key); val != "" {
			cb(key, val)
		}
	}
	for _, o := range t.Other {
		cb(o.Key, o.Val)
	}
}

// ToJSON appends the tags as a JSON object to dst, without allocations
func (t *Tags) ToJSON(dst []byte) []byte {
	dst = append(dst, '{')
	n := len(dst)
	key := func(k string) {
		if len(dst) > n {
			dst = append(dst, ',')
		}
		dst = append(dst, '"')
		dst = json.Ascii(dst, json.B(k))
		dst = append(dst, `":"`...)
	}
	str := func(k, v string) {
		if v != "" {
			key(k)
			dst = append(json.Ascii(dst, json.B(v)), '"')
		}
	}
	addr := func(k string, a netip.Addr) {
		if a.IsValid() {
			key(k)
			dst = append(a.AppendTo(dst), '"')
		}
	}
	asn := func(k string, v uint32) {
		if v != 0 {
			key(k)
			dst = append(strconv.AppendUint(dst, uint64(v), 10), '"')
		}
	}

	// NB: in the order of Each
	str("COLLECTOR", t.Collector)
	asn("LOCAL_AS", t.LocalAS)
	addr("LOCAL_IP", t.LocalIP)
	asn("PEER_AS", t.PeerAS)
	addr("PEER_ID", t.PeerID)
	addr("PEER_IP", t.PeerIP)
	str("ROUTER", t.Router)
	str("SRC", t.Src)
	for _, o := range t.Other {
		str(o.Key, o.Val)
	}
	return append(dst, '}')
}

// FromJSON sets the tags in a JSON object src
func (t *Tags) FromJSON(src []byte) error {
	return json.ObjectEach(src, func(key string, val []byte, typ json.Type) error {
		// NB: key and val alias src, which the reader re-uses: copy them
		t.Set(strings.Clone(key), string(val))
		return nil
	})
}

func addrString(a netip.Addr) string {
	if a.IsValid() {
		return a.String()
	}
	return ""
}

func asString(as uint32) string {
	if as != 0 {
		return strconv.FormatUint(uint64(as), 10)
	}
	return ""
}

func parseAS(s string) uint32 {
	v, _ := strconv.ParseUint(s, 10, 32)
	return uint32(v)
}
