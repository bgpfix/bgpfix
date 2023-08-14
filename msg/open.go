package msg

import (
	"errors"
	"fmt"
	"math"
	"net/netip"
	"strconv"

	"github.com/bgpfix/bgpfix/caps"
	"github.com/bgpfix/bgpfix/json"
)

// Open represents a BGP OPEN message
type Open struct {
	Msg *Msg // parent BGP message

	Version    byte       // must be 4
	ASN        uint16     // 2-byte local ASN
	HoldTime   uint16     // proposed hold time
	Identifier netip.Addr // router identifier
	Params     []byte     // raw Optional Parameters
	ParamsExt  bool       // true iff Params use extended length

	Caps caps.Caps // BGP capabilities, usually parsed from Params
}

const (
	OPEN_MINLEN   = 29 - MSG_HEADLEN // rfc4271/4.2
	OPEN_VERSION  = 4
	OPEN_HOLDTIME = 90

	PARAM_CAPS   = 2
	PARAM_EXTLEN = 255

	AS_TRANS = 23456
)

// Init initializes o to use parent m
func (o *Open) Init(m *Msg) {
	o.Msg = m
	o.Identifier = netip.IPv4Unspecified()
	o.Version = OPEN_VERSION
	// NB: no o.Caps.Init()
}

// Reset prepares o for re-use
func (o *Open) Reset() {
	o.Params = nil
	o.ParamsExt = false
	o.Caps.Reset()
}

// Parse parses msg.Data as BGP OPEN
func (o *Open) Parse() error {
	buf := o.Msg.Data
	if len(buf) < OPEN_MINLEN {
		return ErrShort
	}

	o.Version = buf[0]
	if o.Version != OPEN_VERSION {
		return ErrVersion
	}
	o.ASN = msb.Uint16(buf[1:3])
	o.HoldTime = msb.Uint16(buf[3:5])
	o.Identifier = netip.AddrFrom4([4]byte(buf[5:9]))

	// parse optional parameters
	pslen := int(buf[9])
	if pslen > 0 {
		params, ext := buf[10:], false

		// extended length?
		if len(params) >= 3 && params[0] == PARAM_EXTLEN {
			ext = true
			pslen = int(msb.Uint16(params[1:3]))
			params = params[3:]
		}

		// double-check params length
		if len(params) != pslen {
			return ErrParams
		}

		o.Params = params
		o.ParamsExt = ext
	}

	return nil
}

// ParseCaps parses all capability codes from Params to Caps
func (o *Open) ParseCaps() error {
	var (
		params = o.Params // all parameters
		ptyp   byte       // parameter type
		plen   int        // parameter length
		pval   []byte     // parameter value
		errs   []error    // capability errors
		cps    caps.Caps  // parsed capabilities
	)

	// parse params one-by-one, in practice there's only the
	// capabilities param, or we return an error
	cps.Init()
	for len(params) > 0 {
		if o.ParamsExt {
			if len(params) < 3 {
				return ErrParams
			}
			ptyp = params[0]
			plen = int(msb.Uint16(params[1:3]))
			pval = params[3:]
		} else {
			if len(params) < 2 {
				return ErrParams
			}
			ptyp = params[0]
			plen = int(params[1])
			pval = params[2:]
		}

		// double-check param length
		if len(pval) < plen {
			return ErrParams
		} else {
			params = pval[plen:]
			pval = pval[:plen]
		}

		// we only support capabilities
		if ptyp != PARAM_CAPS {
			return ErrParams
		}

		// parse capabilities
		for len(pval) > 0 {
			if len(pval) < 2 {
				return ErrCaps
			}
			cc, clen, cval := caps.Code(pval[0]), int(pval[1]), pval[2:]
			if len(cval) < clen {
				return ErrCaps
			} else {
				pval = cval[clen:]
				cval = cval[:clen]
			}

			// fetch cap
			cap := cps.Use(cc)
			if cap == nil {
				continue // should not happen
			}

			// try parsing
			if err := cap.Unmarshal(cval, cps); err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", cc, err))
			}
		}
	}

	// any errors?
	if len(errs) > 0 {
		return fmt.Errorf("%w: %w", ErrCaps, errors.Join(errs...))
	}

	// store
	o.Caps = cps
	return nil
}

// SetASN sets local ASN number in o and its AS4
func (o *Open) SetASN(asn int) {
	// o'rlly?
	if asn < 0 || asn > math.MaxUint32 {
		asn = 0
	}

	if asn <= math.MaxUint16 {
		o.ASN = uint16(asn)
	} else {
		o.ASN = AS_TRANS
	}

	if c, ok := o.Caps.Use(caps.CAP_AS4).(*caps.AS4); ok {
		c.ASN = uint32(asn)
	}
}

// GetASN returns the local ASN, preferably from AS4
func (o *Open) GetASN() int {
	if c, ok := o.Caps.Get(caps.CAP_AS4).(*caps.AS4); ok {
		return int(c.ASN)
	} else {
		return int(o.ASN)
	}
}

// Marshal marshals o to o.Msg and returns it
func (o *Open) Marshal() error {
	// check params length
	switch plen := len(o.Params); {
	case plen > math.MaxUint16:
		return fmt.Errorf("Marshal: Params too long: %w (%d)", ErrLength, plen)
	case plen > math.MaxUint8 && !o.ParamsExt:
		return fmt.Errorf("Marshal: ParamsExt disabled: %w (%d)", ErrLength, plen)
	}

	msg := o.Msg
	buf := msg.buf[:0]
	buf = append(buf, o.Version)
	buf = msb.AppendUint16(buf, o.ASN)
	buf = msb.AppendUint16(buf, o.HoldTime)
	buf = append(buf, o.Identifier.AsSlice()...)

	// optional parameters
	if o.ParamsExt {
		buf = append(buf, 255, PARAM_EXTLEN)
		buf = msb.AppendUint16(buf, uint16(len(o.Params)))
	} else {
		buf = append(buf, byte(len(o.Params)))
	}
	buf = append(buf, o.Params...)

	msg.buf = buf
	msg.Data = buf
	msg.ref = false
	return nil
}

// MarshalCaps marshals o.Caps into o.Params. Sets o.ParamsExt.
func (o *Open) MarshalCaps() error {
	// NB: avoid o.Params[:0] as it might be referencing another slice
	o.Params = nil

	// marshal one-by-one
	var raw []byte
	o.Caps.Each(func(i int, cc caps.Code, c caps.Cap) {
		raw = c.Marshal(raw)
	})

	// done?
	if len(raw) == 0 {
		return nil
	}

	// check *parameter* length
	switch plen := len(raw) + 2; { // 2 for param Type and Length
	case plen > math.MaxUint16:
		return fmt.Errorf("MarshalCaps: too long: %w (%d)", ErrLength, plen)
	case plen > 255:
		o.ParamsExt = true
	default:
		o.ParamsExt = false // avoid if not neccessary
	}

	// encode as new o.Params
	p := o.Params
	p = append(p, PARAM_CAPS)
	if o.ParamsExt {
		p = msb.AppendUint16(p, uint16(len(raw)))
	} else {
		p = append(p, byte(len(raw)))
	}
	p = append(p, raw...)
	o.Params = p

	return nil
}

// String dumps o to JSON
func (o *Open) String() string {
	return string(o.ToJSON(nil))
}

// ToJSON appends JSON representation of o to dst
func (o *Open) ToJSON(dst []byte) []byte {
	dst = append(dst, `{"bgp":`...)
	dst = strconv.AppendUint(dst, uint64(o.Version), 10)

	dst = append(dst, `,"asn":`...)
	dst = strconv.AppendUint(dst, uint64(o.GetASN()), 10)

	dst = append(dst, `,"id":"`...)
	dst = o.Identifier.AppendTo(dst)

	dst = append(dst, `","hold":`...)
	dst = strconv.AppendUint(dst, uint64(o.HoldTime), 10)

	if o.Caps.Valid() {
		dst = append(dst, `,"caps":`...)
		dst = o.Caps.ToJSON(dst)
	} else {
		dst = append(dst, `,"params":`...)
		dst = json.Hex(dst, o.Params)
	}

	dst = append(dst, '}')
	return dst
}

// FromJSON reads o JSON representation from src
func (o *Open) FromJSON(src []byte) error {
	return nil // TODO
}
