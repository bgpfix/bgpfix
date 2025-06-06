package caps

import (
	"slices"

	"github.com/bgpfix/bgpfix/afi"
	"github.com/bgpfix/bgpfix/dir"
	"github.com/bgpfix/bgpfix/json"
)

// AddPath implements CAP_ADDPATH rfc7911
type AddPath struct {
	// Proto maps AFI+SAFI pairs to Send/Receive directions
	Proto map[afi.AS]AddPathDir
}

//go:generate go run github.com/dmarkham/enumer -type AddPathDir -trimprefix ADDPATH_
type AddPathDir uint8

// re-use values used in the dir package; assume we're the L side
const (
	ADDPATH_RECEIVE AddPathDir = AddPathDir(dir.DIR_L)
	ADDPATH_SEND    AddPathDir = AddPathDir(dir.DIR_R)
	ADDPATH_BIDIR   AddPathDir = AddPathDir(dir.DIR_LR)
)

func NewAddPath(cc Code) Cap {
	return &AddPath{make(map[afi.AS]AddPathDir)}
}

// Unmarshal parses wire representation from src.
// It must support multiple calls for the same message.
func (c *AddPath) Unmarshal(src []byte, caps Caps) error {
	for len(src) > 0 {
		if len(src) < 4 {
			return ErrLength
		}

		as := afi.NewASBytes(src[0:3]) // afi+safi
		sr := AddPathDir(src[3])       // send/receive
		src = src[4:]

		if sr.IsAAddPathDir() {
			c.Add(as, sr)
		} else {
			return ErrValue
		}
	}
	return nil
}

// Marshal appends wire representation to dst, including code and length.
// Return nil to skip this capability.
func (c *AddPath) Marshal(dst []byte) []byte {
	for _, afv := range c.Sorted() {
		dst = append(dst, byte(CAP_ADDPATH), 4)
		dst = afv.Marshal4(dst)

	}
	return dst
}

// Add adds ADD_PATH for AFI+SAIF pair in as, and the Send/Receive value in dir.
// The value in sr must already be valid.
func (c *AddPath) Add(as afi.AS, dir AddPathDir) {
	c.Proto[as] = dir
}

// Has returns true iff ADD_PATH is enabled for AFI+SAFI pair in the dir direction.
func (c *AddPath) Has(as afi.AS, dir AddPathDir) bool {
	return c != nil && c.Proto[as]&dir != 0
}

// AddPathEnabled returns true iff ADD_PATH is enabled in given direction for as
func (cps *Caps) AddPathEnabled(as afi.AS, dst dir.Dir) bool {
	ap, ok := cps.Get(CAP_ADDPATH).(*AddPath)
	if !ok {
		return false
	}

	if dst&dir.DIR_R != 0 {
		// ie. we are L sending to R
		return ap.Has(as, ADDPATH_SEND)
	} else {
		// ie. we are L receiving from R
		return ap.Has(as, ADDPATH_RECEIVE)
	}
}

// Drop drops ADD_PATH for AFI+SAFI pair in as, whatever the Send/Receive is.
func (c *AddPath) Drop(as afi.AS) {
	delete(c.Proto, as)
}

// Sorted returns all valid AFI+SAFI pairs in sorted order,
// with their Send/Receive encoded as VAL in ASV.
func (c *AddPath) Sorted() (dst []afi.ASV) {
	for as, dir := range c.Proto {
		if dir.IsAAddPathDir() {
			dst = append(dst, as.AddVal(uint32(dir)))
		}
	}
	slices.Sort(dst)
	return
}

// ToJSON appends JSON representation of the value to dst
func (c *AddPath) ToJSON(dst []byte) []byte {
	dst = append(dst, '[')
	for i, afv := range c.Sorted() {
		if i > 0 {
			dst = append(dst, ',')
		}

		dir := AddPathDir(afv.Val())
		dst = afv.ToJSON(dst, dir.String())
	}
	return append(dst, ']')
}

// FromJSON reads from JSON representation in src
func (c *AddPath) FromJSON(src []byte) (err error) {
	return json.ArrayEach(src, func(key int, val []byte, typ json.Type) error {
		var afv afi.ASV
		err := afv.FromJSON(val, func(s string) (uint32, error) {
			dir, err := AddPathDirString(s)
			return uint32(dir), err
		})
		if err != nil {
			return err
		}
		c.Proto[afv.AF()] = AddPathDir(afv.Val())
		return nil
	})
}

// Intersect returns a new instance that represents its intersection with cap2.
// cr = caps sent from L to R, cl = caps sent from R to L
func (cr *AddPath) Intersect(cap2 Cap) Cap {
	// ADD_PATH sent in R direction
	cl, ok := cap2.(*AddPath)
	if !ok {
		return nil
	}

	// the result
	dst := &AddPath{
		Proto: make(map[afi.AS]AddPathDir),
	}

	// for every AFI+SAFI from R
	for as, fromR := range cl.Proto {
		fromL := cr.Proto[as] // check what was sent from L
		var final AddPathDir  // negotiated

		// can L send?
		if fromL&ADDPATH_SEND != 0 && fromR&ADDPATH_RECEIVE != 0 {
			final |= ADDPATH_SEND
		}

		// can L receive?
		if fromL&ADDPATH_RECEIVE != 0 && fromR&ADDPATH_SEND != 0 {
			final |= ADDPATH_RECEIVE
		}

		// double-sure its valid
		if final.IsAAddPathDir() {
			dst.Proto[as] = final
		}
	}

	return dst
}
