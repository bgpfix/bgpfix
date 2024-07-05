package caps

import (
	"slices"

	"github.com/bgpfix/bgpfix/af"
	"github.com/bgpfix/bgpfix/json"
)

// AddPath implements CAP_ADDPATH rfc7911
type AddPath struct {
	// Proto maps AFI+SAFI pairs to Send/Receive directions
	Proto map[af.AF]AddPathDir
}

//go:generate go run github.com/dmarkham/enumer -type AddPathDir -trimprefix ADDPATH_
type AddPathDir uint8

// the only valid values for the Send/Receive field
const (
	ADDPATH_RECEIVE AddPathDir = 0b01
	ADDPATH_SEND    AddPathDir = 0b10
	ADDPATH_BIDIR   AddPathDir = 0b11
)

func NewAddPath(cc Code) Cap {
	return &AddPath{make(map[af.AF]AddPathDir)}
}

// Unmarshal parses wire representation from src.
// It must support multiple calls for the same message.
func (c *AddPath) Unmarshal(src []byte, caps Caps) error {
	for len(src) > 0 {
		if len(src) < 4 {
			return ErrLength
		}
		as := af.NewAFBytes(src[0:3]) // afi+safi
		sr := AddPathDir(src[3])      // send/receive
		if !sr.IsAAddPathDir() {
			return ErrValue
		}
		c.Add(as, sr)
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
func (c *AddPath) Add(as af.AF, dir AddPathDir) {
	c.Proto[as] = dir
}

// Has returns true iff ADD_PATH is enabled for AFI+SAFI pair in the dir direction.
func (c *AddPath) Has(as af.AF, dir AddPathDir) bool {
	return c != nil && c.Proto[as]&dir != 0
}

// AddPathHasSend returns true iff cps has ADD_PATH enabled in the Send direction
func (cps *Caps) AddPathHasSend(as af.AF) bool {
	ap, ok := cps.Get(CAP_ADDPATH).(*AddPath)
	return ok && ap.Has(as, ADDPATH_SEND)
}

// AddPathHasReceive returns true iff cps has ADD_PATH enabled in the Receive direction
func (cps *Caps) AddPathHasReceive(as af.AF) bool {
	ap, ok := cps.Get(CAP_ADDPATH).(*AddPath)
	return ok && ap.Has(as, ADDPATH_RECEIVE)
}

// Drop drops ADD_PATH for AFI+SAFI pair in as, whatever the Send/Receive is.
func (c *AddPath) Drop(as af.AF) {
	delete(c.Proto, as)
}

// Sorted returns all AFI+SAFI pairs in sorted order,
// with their Send/Receive encoded as VAL in AFV.
func (c *AddPath) Sorted() (dst []af.AFV) {
	for as, dir := range c.Proto {
		dst = append(dst, as.AddVal(uint32(dir)))
	}
	slices.Sort(dst)
	return
}

// ToJSON appends JSON representation of the value to dst
func (c *AddPath) ToJSON(dst []byte) []byte {
	dst = append(dst, '{')
	for i, afv := range c.Sorted() {
		if i > 0 {
			dst = append(dst, ',')
		}

		dir := AddPathDir(afv.Val())
		dst = afv.ToJSON(dst, dir.String())
	}

	return append(dst, '}')
}

// FromJSON reads from JSON representation in src
func (c *AddPath) FromJSON(src []byte) (err error) {
	return json.ArrayEach(src, func(key int, val []byte, typ json.Type) error {
		var asv af.AFV
		err := asv.FromJSON(val, func(s string) (uint32, error) {
			dir, err := AddPathDirString(s)
			return uint32(dir), err
		})
		if err != nil {
			return err
		}
		c.Proto[asv.DropVal()] = AddPathDir(asv.Val())
		return nil
	})
}

// Intersect returns a new instance that represents its intersection with cap2.
// c1 is received from peer, cap2 is what we sent.
func (c1 *AddPath) Intersect(cap2 Cap) Cap {
	c2, ok := cap2.(*AddPath)
	if !ok {
		return nil
	}

	dst := &AddPath{
		Proto: make(map[af.AF]AddPathDir),
	}

	for as, peer := range c1.Proto {
		local := c2.Proto[as]  // what we sent for AFI+SAFI
		final := AddPathDir(0) // negotiated for AFI+SAFI

		// can we send ADD_PATH?
		if local&ADDPATH_SEND != 0 && peer&ADDPATH_RECEIVE != 0 {
			final |= ADDPATH_SEND
		}

		// should we receive ADD_PATH?
		if local&ADDPATH_RECEIVE != 0 && peer&ADDPATH_SEND != 0 {
			final |= ADDPATH_RECEIVE
		}

		dst.Proto[as] = final
	}

	return dst
}
