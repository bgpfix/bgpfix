package attrs

import (
	"fmt"
	"iter"
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
	return &Aspath{
		CodeFlags: at,
		Segments:  make([]AspathSegment, 0, 1),
	}
}

func (a *Aspath) Reset() {
	a.Segments = a.Segments[:0]
}

// Clone creates a deep copy of the Aspath object.
func (a *Aspath) Clone() *Aspath {
	a2 := &Aspath{
		CodeFlags: a.CodeFlags,
		Segments:  slices.Clone(a.Segments),
	}
	for i := range a.Segments {
		a2.Segments[i].List = slices.Clone(a.Segments[i].List)
	}
	return a2
}

// Len returns the number of ASNs in the AS_PATH, treating non-empty AS_SETs as 1.
func (a *Aspath) Len() int {
	l := 0
	for i := range a.Segments {
		seg := &a.Segments[i]
		if seg.IsSet {
			l += min(len(seg.List), 1)
		} else {
			l += len(seg.List)
		}
	}
	return l
}

// Hops returns an iterator over the AS_PATH hops.
// Each hop is either a single ASN (len=1) or a list of AS_SET members (len>1).
func (a *Aspath) Hops() iter.Seq2[int, []uint32] {
	return func(yield func(int, []uint32) bool) {
		done := 0
		for i := range a.Segments {
			seg := &a.Segments[i]
			if seg.IsSet {
				if !yield(done, seg.List) {
					return
				} else {
					done++
				}
			} else {
				for j := range seg.List {
					if !yield(done, seg.List[j:j+1]) {
						return
					} else {
						done++
					}
				}
			}
		}
	}
}

// Hop returns the AS_PATH hop at given index (zero-based).
// In case index < 0, it counts backwards from the end.
// NOTE: this function assumes a.Valid() == true.
func (a *Aspath) Hop(index int) []uint32 {
	sl := len(a.Segments)
	if sl == 0 {
		return nil
	}

	if index >= 0 {
		// special case: the first hop
		if index == 0 {
			first := &a.Segments[0]
			ll := len(first.List)
			if ll == 0 {
				return nil
			} else if first.IsSet {
				return first.List
			} else {
				return first.List[:1]
			}
		}

		for i := range a.Segments {
			seg := &a.Segments[i]
			if seg.IsSet {
				if index == 0 {
					return seg.List
				} else {
					index--
				}
			} else {
				ll := len(seg.List)
				if index < ll {
					return seg.List[index : index+1]
				} else {
					index -= ll
				}
			}
		}
	} else { // negative index
		// special case: the last hop
		if index == -1 {
			last := &a.Segments[sl-1]
			ll := len(last.List)
			if ll == 0 {
				return nil
			} else if last.IsSet {
				return last.List
			} else {
				return last.List[ll-1:]
			}
		}

		// convert to positive, iterate from back
		index = -index - 1
		for i := sl - 1; i >= 0; i-- {
			seg := &a.Segments[i]
			if seg.IsSet {
				if index == 0 {
					return seg.List
				} else {
					index--
				}
			} else {
				sl := len(seg.List)
				if index < sl {
					return seg.List[sl-index-1 : sl-index]
				} else {
					index -= sl
				}
			}
		}
	}
	return nil
}

// Append appends a hop to the AS_PATH.
// If the hop is a single ASN, it is appended to the last segment.
// Otherwise, it is appended as a new AS_SET segment.
func (a *Aspath) Append(hop []uint32) {
	switch len(hop) {
	case 0:
		return // invalid
	case 1:
		l := len(a.Segments) - 1
		if l < 0 || a.Segments[l].IsSet {
			a.Segments = append(a.Segments, AspathSegment{})
			l++
		}
		seg := &a.Segments[l]
		seg.List = append(seg.List, hop...)
	default:
		a.Segments = append(a.Segments, AspathSegment{
			IsSet: true,
			List:  slices.Clone(hop),
		})
	}
}

// Set sets the AS_PATH to be a single segment with given hops
func (a *Aspath) Set(hops []uint32) {
	a.Segments = append(a.Segments[:0], AspathSegment{
		List: slices.Clone(hops),
	})
}

// Valid returns true iff the AS_PATH is valid
func (ap *Aspath) Valid() bool {
	return ap != nil && len(ap.Segments) > 0 && len(ap.Segments[0].List) > 0
}

func (a *Aspath) Unmarshal(raw []byte, cps caps.Caps, dir dir.Dir) error {
	// support an actually common case: empty AS_PATH
	if len(raw) == 0 {
		return nil
	}
	buf := raw
	sgl := len(a.Segments)

	// asn length
	asnlen := 2
	if a.Code() == ATTR_AS4PATH || cps.Has(caps.CAP_AS4) {
		asnlen = 4
	}

	// can retry with 2-byte ASNs?
	retry2 := func() bool {
		if asnlen == 4 && a.Code() == ATTR_ASPATH && cps.Has(caps.CAP_AS_GUESS) {
			asnlen = 2
			buf = raw
			a.Segments = a.Segments[:sgl]
			return true
		} else {
			return false
		}
	}

	for len(buf) > 0 {
		var seg AspathSegment

		// makes sense?
		if len(buf) < 2 || buf[1] == 0 {
			if retry2() {
				continue
			} else {
				return ErrLength
			}
		}

		// type: is AS_SET?
		switch buf[0] {
		case 1:
			seg.IsSet = true // is AS_SET
		case 2:
			seg.IsSet = false // is AS_SEQUENCE
		default:
			if retry2() {
				continue
			} else {
				return fmt.Errorf("%w: %d", ErrSegType, buf[0])
			}
		}

		// hops: total length makes sense?
		tl := 2 + asnlen*int(buf[1])
		if len(buf) < tl {
			if retry2() {
				continue
			} else {
				return fmt.Errorf("%w: %d < 2+%d*%d", ErrSegLen, len(buf), asnlen, buf[1])
			}
		}

		// read ASNs
		todo := buf[2:]
		seg.List = make([]uint32, 0, len(todo)/asnlen)
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

// HasAsn returns true if ap has given asn anywhere in AS_PATH.
// If as_set=1, scans AS_SETs only; if -1, ignores AS_SETs completely.
func (ap *Aspath) HasAsn(asn uint32, as_set int) bool {
	for si := range ap.Segments {
		seg := &ap.Segments[si]
		switch as_set {
		case 1: // require AS_SETs
			if !seg.IsSet {
				continue
			}
		case -1: // ignore AS_SETs
			if seg.IsSet {
				continue
			}
		}
		if slices.Index(ap.Segments[si].List, asn) != -1 {
			return true
		}
	}
	return false
}

// HasOrigin returns true iff ap has given asn at the origin.
// If as_set=1, requires an AS_SET origin; if -1, requires a non-AS_SET origin.
// For an AS_SET origin to match the asn must be one of its elements.
func (ap *Aspath) HasOrigin(asn uint32, as_set int) bool {
	lastseg := len(ap.Segments) - 1
	if lastseg < 0 {
		return false // no segments?
	}

	seg := &ap.Segments[lastseg]
	segl := len(seg.List)
	if segl == 0 {
		return false // no ASes in the last segment?!
	}

	switch as_set {
	case 1: // require AS_SETs
		if !seg.IsSet {
			return false
		}
	case -1: // ignore AS_SETs
		if seg.IsSet {
			return false
		}
	}

	if seg.IsSet {
		return slices.Index(seg.List, asn) != -1
	} else {
		return seg.List[segl-1] == asn
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
