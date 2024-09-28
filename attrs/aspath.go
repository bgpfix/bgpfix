package attrs

import (
	"fmt"
	"slices"
	"strconv"

	"github.com/bgpfix/bgpfix/caps"
	"github.com/bgpfix/bgpfix/dir"
	"github.com/bgpfix/bgpfix/json"
)

// Aspath represents ATTR_ASPATH or ATTR_AS4PATH
type Aspath struct {
	CodeFlags
	Segments []AspathSegment
}

// AspathSegment represents an AS_PATH segment
type AspathSegment struct {
	IsSet bool     // true iff segment is an AS_SET
	List  []uint32 // list of AS numbers
}

func NewAspath(at CodeFlags) Attr {
	return &Aspath{CodeFlags: at}
}

func (a *Aspath) Unmarshal(buf []byte, cps caps.Caps, dir dir.Dir) error {
	// support an actually common case: empty AS_PATH
	if len(buf) == 0 {
		return nil
	}

	// asn length
	asnlen := 2
	if a.Code() == ATTR_AS4PATH || cps.Has(caps.CAP_AS4) {
		asnlen = 4
	}

	for len(buf) >= 2 {
		var seg AspathSegment

		// is AS_SET?
		switch buf[0] {
		case 1:
			seg.IsSet = true // is AS_SET
		case 2:
			// is AS_SEQUENCE
		default:
			return fmt.Errorf("%w: %d", ErrSegType, buf[0])
		}

		// total length?
		tl := 2 + asnlen*int(buf[1])
		if len(buf) < tl {
			return ErrSegLen
		}

		// read ASNs
		todo := buf[2:]
		for len(todo) >= asnlen {
			if asnlen == 4 {
				seg.List = append(seg.List, msb.Uint32(todo))
			} else {
				seg.List = append(seg.List, uint32(msb.Uint16(todo)))
			}
			todo = todo[asnlen:]
		}

		// store segment, go to next
		if len(seg.List) > 0 {
			a.Segments = append(a.Segments, seg)
		}
		buf = buf[tl:]
	}

	if len(buf) == 0 {
		return nil
	} else {
		return ErrLength
	}
}

func (a *Aspath) Marshal(dst []byte, cps caps.Caps, dir dir.Dir) []byte {
	// asn length
	asnlen := 2
	if a.Code() == ATTR_AS4PATH || cps.Has(caps.CAP_AS4) {
		asnlen = 4
	}

	// total length
	l := 0
	for _, seg := range a.Segments {
		l += 1 + 1 + asnlen*len(seg.List)
	}

	// attr flags, code, length
	dst = a.CodeFlags.MarshalLen(dst, l)

	// attr value
	for _, seg := range a.Segments {
		if seg.IsSet {
			dst = append(dst, 1)
		} else {
			dst = append(dst, 2)
		}
		dst = append(dst, byte(len(seg.List)))
		for _, hop := range seg.List {
			if asnlen == 4 {
				dst = msb.AppendUint32(dst, hop)
			} else {
				dst = msb.AppendUint16(dst, uint16(hop))
			}
		}
	}

	return dst
}

func (a *Aspath) ToJSON(dst []byte) []byte {
	dst = append(dst, '[')
	for i := range a.Segments {
		seg := &a.Segments[i]
		if i > 0 {
			dst = append(dst, ',')
		}

		if seg.IsSet {
			dst = append(dst, '[')
		}

		for j, asn := range seg.List {
			if j > 0 {
				dst = append(dst, ',')
			}
			dst = strconv.AppendUint(dst, uint64(asn), 10)
		}

		if seg.IsSet {
			dst = append(dst, ']')
		}
	}
	dst = append(dst, ']')
	return dst
}

func (a *Aspath) String() string {
	if a != nil {
		return json.S(a.ToJSON(nil))
	} else {
		return "(nil)"
	}
}

func (a *Aspath) FromJSON(src []byte) error {
	var seg AspathSegment

	// seg_add adds asn to seg.List
	seg_add := func(asn []byte) error {
		v, err := strconv.ParseUint(json.S(asn), 0, 32)
		if err == nil {
			seg.List = append(seg.List, uint32(v))
		}
		return err
	}

	// seg_push adds seg to a.Segments if needed
	seg_push := func() {
		if len(seg.List) > 0 {
			a.Segments = append(a.Segments, seg)
		}
		seg = AspathSegment{} // clear
	}

	err := json.ArrayEach(src, func(_ int, val []byte, typ json.Type) error {
		switch typ {
		case json.ARRAY: // is an AS_SET
			seg_push()
			set_err := json.ArrayEach(val, func(_ int, set_val []byte, _ json.Type) error {
				return seg_add(set_val)
			})
			seg.IsSet = true
			seg_push()
			return set_err
		default:
			return seg_add(val)
		}
	})
	seg_push()
	return err
}

// HasAsn returns true if ap has given asn anywhere in AS_PATH
func (ap *Aspath) HasAsn(asn uint32) bool {
	for si := range ap.Segments {
		if slices.Index(ap.Segments[si].List, asn) != -1 {
			return true
		}
	}
	return false
}

// HasOrigin returns true iff ap has given asn at the origin.
// In case of origin AS sets, asn must be one of the set elements.
func (ap *Aspath) HasOrigin(asn uint32) bool {
	lastseg := len(ap.Segments) - 1
	if lastseg < 0 {
		return false // no segments?
	}

	seg := &ap.Segments[lastseg]
	if sl := len(seg.List); sl == 0 {
		return false // no ASes in the last segment?!
	} else if seg.IsSet {
		return slices.Index(seg.List, asn) != -1
	} else {
		return seg.List[sl-1] == asn
	}
}

// Origin returns the last AS in AS_PATH, or 0 on error.
// It treats AS_SET origins as errors.
func (ap *Aspath) Origin() uint32 {
	if ap == nil {
		return 0
	}

	lastseg := len(ap.Segments) - 1
	if lastseg < 0 {
		return 0 // no segments?
	}

	seg := &ap.Segments[lastseg]
	if sl := len(seg.List); sl == 0 {
		return 0 // no ASes in the last segment?!
	} else if seg.IsSet {
		return 0 // treat as error
	} else {
		return seg.List[sl-1]
	}
}
