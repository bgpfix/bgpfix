package caps

import (
	"errors"
	"sort"
	"strconv"

	"github.com/bgpfix/bgpfix/af"
	"github.com/bgpfix/bgpfix/json"
)

var (
	errInvalidAddPathLength      = errors.New("invalid add-path length")
	errInvalidAddPathSendReceive = errors.New("invalid send/receive byte")
)

func NewAddPath(cc Code) Cap {
	return &AddPath{make(map[af.AF]AddPathDirection)}
}

type AddPath struct {
	Proto map[af.AF]AddPathDirection
}

type AddPathDirection struct {
	Send    bool
	Receive bool
}

// Unmarshal parses wire representation from src.
// It must support multiple calls for the same message.
func (c *AddPath) Unmarshal(src []byte, caps Caps) error {
	if len(src)%4 != 0 {
		return ErrLength
	}
	for i := 0; i < len(src); i += 4 {
		afi := af.AFI(src[i]<<8 | src[i+1])
		safi := af.SAFI(src[i+2])
		d := AddPathDirection{}
		switch uint8(src[i+3]) {
		case 1:
			d.Receive = true
		case 2:
			d.Send = true
		case 3:
			d.Send = true
			d.Receive = true
		default:
			return errInvalidAddPathSendReceive
		}
		c.Add(afi, safi, d)
	}

	return nil
}

// Marshal appends wire representation to dst, including code and length.
// Return nil to skip this capability.
func (c *AddPath) Marshal(dst []byte) []byte {
	for afisafi, d := range c.Proto {
		dst = append(dst, byte(CAP_ADDPATH), 4)
		dst = msb.AppendUint16(dst, uint16(afisafi.Afi()))
		dst = append(dst, byte(afisafi.Safi()))
		dst = append(dst, d.sendReceive())
	}
	return dst
}

func (c *AddPath) Add(afi af.AFI, safi af.SAFI, dir AddPathDirection) {
	c.Proto[af.New(afi, safi)] = dir
}

func (c *AddPath) HasSend(afi af.AFI, safi af.SAFI) bool {
	if v, has := c.Proto[af.New(afi, safi)]; has {
		return v.Send
	}
	return false
}

func (c *AddPath) HasReceive(afi af.AFI, safi af.SAFI) bool {
	if v, has := c.Proto[af.New(afi, safi)]; has {
		return v.Receive
	}
	return false
}

func (d AddPathDirection) sendReceive() byte {
	val := byte(0)
	if d.Receive {
		val |= 1
	}
	if d.Send {
		val |= 2
	}
	return val
}

func (c *AddPath) Sorted() (dst []af.AFV) {
	for as, val := range c.Proto {
		dst = append(dst, af.NewAFV(as.Afi(), as.Safi(), uint32(val.sendReceive())))
	}
	sort.Slice(dst, func(i, j int) bool {
		return dst[i] < dst[j]
	})
	return
}

// ToJSON appends JSON representation of the value to dst
func (c *AddPath) ToJSON(dst []byte) []byte {
	dst = append(dst, '{')
	for i, v := range c.Sorted() {
		if i > 0 {
			dst = append(dst, ',')
		}
		afisafi := af.New(v.Afi(), v.Safi())
		dst = afisafi.ToJSON(dst)
		dst = append(dst, ':')
		dst = strconv.AppendUint(dst, uint64(v.Val()), 10)
	}

	return append(dst, '}')
}

// FromJSON reads from JSON representation in src
func (c *AddPath) FromJSON(src []byte) (err error) {
	afisafi := af.NewAFV(0, 0, 0)
	return json.ArrayEach(src, func(key int, val []byte, typ json.Type) error {
		if err := afisafi.FromJSONAfi(val); err != nil {
			return err
		}
		afValue := af.New(afisafi.Afi(), afisafi.Safi())
		d := AddPathDirection{}
		switch afisafi.Val() {
		case 1:
			d.Send = true
		case 2:
			d.Receive = true
		case 3:
			d.Receive = true
			d.Send = true
		default:
			err = errInvalidAddPathSendReceive
			return err
		}

		c.Proto[afValue] = d
		return nil
	})
}

// c is the capability we receive from the peer
// cap2 is the capability we have sent
func (c *AddPath) Intersect(cap2 Cap) Cap {
	c2, ok := cap2.(*AddPath)
	if !ok {
		return nil
	}

	dst := &AddPath{
		Proto: make(map[af.AF]AddPathDirection),
	}

	for as, val := range c.Proto {
		if val2, has := c2.Proto[as]; has {
			dst.Proto[as] = AddPathDirection{
				Send:    val2.Send && val.Receive,
				Receive: val2.Receive && val.Send,
			}
		}
	}

	return dst
}


func HasReceiveAddPath(cps Caps, afi af.AFI, safi af.SAFI) bool {
	addPathCap, ok := cps.Get(CAP_ADDPATH).(*AddPath)

	return ok && addPathCap != nil && addPathCap.HasReceive(afi, safi)
}

func HasSendAddPath(cps Caps, afi af.AFI, safi af.SAFI) bool {
	addPathCap, ok := cps.Get(CAP_ADDPATH).(*AddPath)

	return ok && addPathCap != nil && addPathCap.HasSend(afi, safi)
}