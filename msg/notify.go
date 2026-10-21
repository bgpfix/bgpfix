package msg

import (
	"strconv"

	"github.com/bgpfix/bgpfix/json"
)

// NOTIFY has no upper layer struct: code, subcode and data are read from msg.Data.

const NOTIFY_MINLEN = 2 // code + subcode

// notifyNames maps code<<8|subcode to a name, subcode 0 names the code itself.
// Sources: rfc4271/6.x, rfc4486, rfc5492, rfc6608, rfc7313, rfc8538, rfc9234, rfc9384.
var notifyNames = map[uint16]string{
	1<<8 | 0: "Message Header Error",
	1<<8 | 1: "Connection Not Synchronized",
	1<<8 | 2: "Bad Message Length",
	1<<8 | 3: "Bad Message Type",

	2<<8 | 0:  "OPEN Message Error",
	2<<8 | 1:  "Unsupported Version Number",
	2<<8 | 2:  "Bad Peer AS",
	2<<8 | 3:  "Bad BGP Identifier",
	2<<8 | 4:  "Unsupported Optional Parameter",
	2<<8 | 6:  "Unacceptable Hold Time",
	2<<8 | 7:  "Unsupported Capability",
	2<<8 | 11: "Role Mismatch",

	3<<8 | 0:  "UPDATE Message Error",
	3<<8 | 1:  "Malformed Attribute List",
	3<<8 | 2:  "Unrecognized Well-known Attribute",
	3<<8 | 3:  "Missing Well-known Attribute",
	3<<8 | 4:  "Attribute Flags Error",
	3<<8 | 5:  "Attribute Length Error",
	3<<8 | 6:  "Invalid ORIGIN Attribute",
	3<<8 | 8:  "Invalid NEXT_HOP Attribute",
	3<<8 | 9:  "Optional Attribute Error",
	3<<8 | 10: "Invalid Network Field",
	3<<8 | 11: "Malformed AS_PATH",

	4<<8 | 0: "Hold Timer Expired",

	5<<8 | 0: "Finite State Machine Error",
	5<<8 | 1: "Unexpected Message in OpenSent",
	5<<8 | 2: "Unexpected Message in OpenConfirm",
	5<<8 | 3: "Unexpected Message in Established",

	6<<8 | 0:  "Cease",
	6<<8 | 1:  "Maximum Number of Prefixes Reached",
	6<<8 | 2:  "Administrative Shutdown",
	6<<8 | 3:  "Peer De-configured",
	6<<8 | 4:  "Administrative Reset",
	6<<8 | 5:  "Connection Rejected",
	6<<8 | 6:  "Other Configuration Change",
	6<<8 | 7:  "Connection Collision Resolution",
	6<<8 | 8:  "Out of Resources",
	6<<8 | 9:  "Hard Reset",
	6<<8 | 10: "BFD Down",

	7<<8 | 0: "ROUTE-REFRESH Message Error",
	7<<8 | 1: "Invalid Message Length",
}

// NotifyName returns a human-readable name for given NOTIFY code and subcode,
// eg. "Cease/Administrative Shutdown". Unknown values are given as numbers.
func NotifyName(code, subcode byte) string {
	c, ok := notifyNames[uint16(code)<<8]
	if !ok {
		c = strconv.Itoa(int(code))
	}
	if subcode == 0 {
		return c
	}
	s, ok := notifyNames[uint16(code)<<8|uint16(subcode)]
	if !ok {
		s = strconv.Itoa(int(subcode))
	}
	return c + "/" + s
}

// Notify returns the code, subcode and data of a NOTIFY message, or zero values if not available.
// The data references msg.Data.
func (msg *Msg) Notify() (code, subcode byte, data []byte) {
	if msg.Type != NOTIFY || len(msg.Data) < NOTIFY_MINLEN {
		return 0, 0, nil
	}
	return msg.Data[0], msg.Data[1], msg.Data[NOTIFY_MINLEN:]
}

// NotifyText returns the shutdown communication (rfc9003) in a NOTIFY message
// with code Cease and subcode Administrative Shutdown or Reset, or nil if not present.
func (msg *Msg) NotifyText() []byte {
	code, subcode, data := msg.Notify()
	if code != 6 || (subcode != 2 && subcode != 4) || len(data) < 2 || int(data[0]) != len(data)-1 {
		return nil
	}
	return data[1:]
}

// notifyToJSON appends NOTIFY JSON object to dst
func (msg *Msg) notifyToJSON(dst []byte) []byte {
	code, subcode, data := msg.Notify()
	dst = append(dst, `{"code":`...)
	dst = strconv.AppendUint(dst, uint64(code), 10)
	dst = append(dst, `,"subcode":`...)
	dst = strconv.AppendUint(dst, uint64(subcode), 10)
	dst = append(dst, `,"name":"`...)
	dst = append(dst, NotifyName(code, subcode)...)
	dst = append(dst, `","data":`...)
	dst = json.Hex(dst, data)
	if text := msg.NotifyText(); text != nil {
		dst = append(dst, `,"text":"`...)
		dst = json.Utf8(dst, text)
		dst = append(dst, '"')
	}
	return append(dst, '}')
}

// notifyFromJSON reads NOTIFY JSON object from src into msg.Data
func (msg *Msg) notifyFromJSON(src []byte) error {
	var code, subcode byte
	var data []byte
	err := json.ObjectEach(src, func(key string, val []byte, typ json.Type) (err error) {
		switch key {
		case "code":
			code, err = json.UnByte(val)
		case "subcode":
			subcode, err = json.UnByte(val)
		case "data":
			data, err = json.UnHex(val, nil)
		}
		return err
	})
	if err != nil {
		return err
	}

	msg.buf = append(append(msg.buf[:0], code, subcode), data...)
	msg.Data = msg.buf
	msg.ref = false
	msg.Upper = NOTIFY
	msg.Version++
	return nil
}
