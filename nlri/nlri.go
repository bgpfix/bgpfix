package nlri

import (
	"net/netip"
	"strconv"
	"strings"

	"github.com/bgpfix/bgpfix/json"
)

// NLRI is Network Layer Reachability Information (RFC4271),
// extended to support ADD_PATH (RFC7911).
type NLRI struct {
	netip.Prefix         // the IP prefix
	PathId       *uint32 // ADD_PATH Path Identifier
}

func ToJSON(dst []byte, src []NLRI) []byte {
	dst = append(dst, '[')
	for i := range src {
		v := &src[i]
		if i > 0 {
			dst = append(dst, ',')
		}
		switch {
		case v.PathId != nil:
			dst = append(dst, `"#`...)
			dst = json.Uint32(dst, *v.PathId)
			dst = append(dst, ':')
		default:
			dst = append(dst, '"')
		}
		dst = v.Prefix.AppendTo(dst)
		dst = append(dst, '"')
	}
	return append(dst, ']')
}

func FromJSON(src []byte, dst []NLRI) ([]NLRI, error) {
	err := json.ArrayEach(src, func(key int, buf []byte, typ json.Type) error {
		var (
			nlri NLRI
			err  error
			s    = json.S(buf)
		)

		if len(s) == 0 {
			return json.ErrValue
		}

		// starts with #? treat as add-path path identifier
		if s[0] == '#' {
			before, after, found := strings.Cut(s[1:], ":")
			if !found || len(before) < 2 {
				return json.ErrValue
			}
			val, err := strconv.ParseUint(before[1:], 10, 32)
			if err != nil {
				return err
			}
			s = after
			id := uint32(val)
			nlri.PathId = &id
		}

		nlri.Prefix, err = netip.ParsePrefix(s)
		if err != nil {
			return err
		}

		dst = append(dst, nlri)
		return nil
	})
	return dst, err
}
