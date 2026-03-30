// Package rtr implements a minimal RPKI-to-Router (RTR) protocol client.
// It supports protocol versions 0 (draft-ietf-sidr-rpki-rtr), 1 (RFC 8210),
// and 2 (draft-ietf-sidrops-8210bis, which adds ASPA).
//
// Usage:
//
//	c := rtr.NewClient(&rtr.Options{
//	    OnROA:       func(...) { /* handle ROA */ },
//	    OnASPA:      func(...) { /* handle ASPA */ },
//	    OnEndOfData: func(...) { /* cache consistent */ },
//	})
//	err := c.Run(ctx, conn)  // blocks; call from reconnection loop
package rtr

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"

	"github.com/rs/zerolog"
)

// Client is a single-endpoint RTR protocol client.
// It can be reused across multiple connections (reconnections).
// All fields except Options must not be modified after the first call to Run.
type Client struct {
	*zerolog.Logger
	Options Options

	mu        sync.Mutex
	wmu       sync.Mutex // protects writes to conn (SendSerial vs dispatch)
	conn      net.Conn   // current connection (nil when Run is not active)
	version   byte       // negotiated protocol version (0 until first CacheResponse)
	sessid    uint16     // current session ID (from CacheResponse)
	serial    uint32     // last serial number received (from EndOfData)
	hasSerial bool       // true once the first EndOfData has been received
}

// NewClient returns a new Client with the given options.
// If opts is nil, DefaultOptions is used (VersionAuto + default logger).
// When opts is non-nil, all fields are used as-is, including Version:
//   - VersionAuto (255): auto-negotiate v2 → v1 → v0 on ErrUnsupVersion
//   - VersionV0/V1/V2: use that version with no fallback
func NewClient(opts *Options) *Client {
	c := &Client{}
	if opts != nil {
		c.Options = *opts
	} else {
		c.Options = DefaultOptions
	}
	if c.Options.Logger != nil {
		c.Logger = c.Options.Logger
	} else {
		l := zerolog.Nop()
		c.Logger = &l
	}
	return c
}

// Run starts an RTR session over conn, processing PDUs until conn closes or ctx is done.
// It sends a Reset Query immediately on connect.
// On receiving Error code ErrUnsupVersion, it automatically downgrades the protocol
// version (v2 → v1 → v0) and retries.
// Returns ctx.Err() if ctx is cancelled, otherwise the connection error.
// The caller is responsible for reconnection.
//
// NB: Run starts one internal goroutine to close conn on ctx cancellation;
// this goroutine exits when Run returns.
func (c *Client) Run(ctx context.Context, conn net.Conn) error {
	c.mu.Lock()
	if c.conn != nil {
		c.mu.Unlock()
		return fmt.Errorf("rtr: Run already active")
	}
	c.conn = conn
	c.mu.Unlock()

	runDone := make(chan struct{})
	defer func() {
		close(runDone)
		c.mu.Lock()
		c.conn = nil
		c.mu.Unlock()
	}()

	// close conn when ctx is cancelled or Run exits
	go func() {
		select {
		case <-ctx.Done():
			conn.Close()
		case <-runDone:
		}
	}()

	// determine starting version (VersionAuto or any value > V2 starts at V2)
	ver := c.Options.Version
	if ver > VersionV2 {
		ver = VersionV2
	}

	// send initial Reset Query
	c.wmu.Lock()
	err := writeResetQuery(conn, ver)
	c.wmu.Unlock()
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	}

	for {
		h, err := readHeader(conn)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}

		payload, err := readPayload(conn, h)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}

		if err := c.dispatch(conn, h, payload, &ver); err != nil {
			return err
		}
	}
}

// SendSerial sends a Serial Query to request incremental updates since the last serial.
// Returns false if no serial is available yet (no full cache received) or not connected.
// Safe to call concurrently with Run from a different goroutine.
func (c *Client) SendSerial() bool {
	c.mu.Lock()
	conn := c.conn
	hasSerial := c.hasSerial
	sessid := c.sessid
	serial := c.serial
	version := c.version
	c.mu.Unlock()

	if conn == nil || !hasSerial {
		return false
	}
	c.wmu.Lock()
	err := writeSerialQuery(conn, version, sessid, serial)
	c.wmu.Unlock()
	return err == nil
}

// Version returns the negotiated protocol version (0 before first CacheResponse).
// Safe to call concurrently with Run.
func (c *Client) Version() byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.version
}

// dispatch processes a single PDU received from the server.
// w is the writer for sending response PDUs (may be nil for read-only testing).
// ver is a pointer to the currently negotiated version (updated on version negotiation).
func (c *Client) dispatch(w io.Writer, h pduHeader, payload []byte, ver *byte) error {
	switch h.Type {

	case PDUCacheResponse:
		c.mu.Lock()
		c.version = h.Version
		c.sessid = h.Session
		c.mu.Unlock()
		if ver != nil {
			*ver = h.Version
		}
		c.Debug().
			Uint8("version", h.Version).
			Uint16("sessid", h.Session).
			Msg("RTR cache response")

	case PDUIPv4Prefix:
		return c.dispatchIPv4(payload)

	case PDUIPv6Prefix:
		return c.dispatchIPv6(payload)

	case PDUAspa:
		return c.dispatchASPA(h, payload)

	case PDUEndOfData:
		return c.dispatchEndOfData(h, payload)

	case PDUCacheReset:
		c.Debug().Msg("RTR cache reset")
		c.mu.Lock()
		c.hasSerial = false
		c.mu.Unlock()
		if c.Options.OnCacheReset != nil {
			c.Options.OnCacheReset()
		}
		if w != nil && ver != nil {
			c.wmu.Lock()
			err := writeResetQuery(w, *ver)
			c.wmu.Unlock()
			return err
		}

	case PDUSerialNotify:
		if len(payload) < 4 {
			return fmt.Errorf("rtr: SerialNotify payload %d < 4", len(payload))
		}
		newSerial := msb.Uint32(payload[0:4])
		c.mu.Lock()
		hasSerial := c.hasSerial
		curSerial := c.serial
		sessid := c.sessid
		c.mu.Unlock()
		c.Debug().Uint32("serial", newSerial).Msg("RTR serial notify")
		if w != nil && ver != nil && hasSerial {
			// NB: session ID change means the cache was reset (RFC 8210 §5.4)
			if h.Session != sessid {
				c.Info().
					Uint16("old", sessid).
					Uint16("new", h.Session).
					Msg("RTR session ID changed in SerialNotify, sending Reset Query")
				c.wmu.Lock()
				err := writeResetQuery(w, *ver)
				c.wmu.Unlock()
				return err
			}
			if newSerial != curSerial {
				c.wmu.Lock()
				err := writeSerialQuery(w, *ver, sessid, curSerial)
				c.wmu.Unlock()
				return err
			}
		}

	case PDUErrorReport:
		code := h.Session
		text := parseErrorText(payload)
		c.Warn().Uint16("code", code).Str("text", text).Msg("RTR error report")
		// auto-negotiate: downgrade protocol version and retry
		if code == ErrUnsupVersion && c.Options.Version == VersionAuto && ver != nil && *ver > VersionV0 {
			*ver--
			c.Info().Uint8("version", *ver).Msg("RTR downgrading protocol version")
			if w != nil {
				c.wmu.Lock()
				err := writeResetQuery(w, *ver)
				c.wmu.Unlock()
				return err
			}
		}
		if c.Options.OnError != nil {
			c.Options.OnError(code, text)
		}

	case PDURouterKey:
		// ignore BGPsec Router Key PDUs

	default:
		c.Debug().Uint8("type", h.Type).Msg("RTR ignoring unknown PDU type")
	}

	return nil
}

func (c *Client) dispatchIPv4(payload []byte) error {
	if len(payload) < 12 {
		return fmt.Errorf("rtr: IPv4 prefix payload %d < 12", len(payload))
	}
	flags := payload[0]
	pfxLen := payload[1]
	maxLen := payload[2]
	// payload[3] = reserved
	addr := netip.AddrFrom4([4]byte{payload[4], payload[5], payload[6], payload[7]})
	asn := msb.Uint32(payload[8:12])
	prefix, err := addr.Prefix(int(pfxLen))
	if err != nil {
		return fmt.Errorf("rtr: invalid IPv4 prefix /%d: %w", pfxLen, err)
	}
	if c.Options.OnROA != nil {
		c.Options.OnROA(flags == FlagAnnounce, prefix.Masked(), maxLen, asn)
	}
	return nil
}

func (c *Client) dispatchIPv6(payload []byte) error {
	if len(payload) < 24 {
		return fmt.Errorf("rtr: IPv6 prefix payload %d < 24", len(payload))
	}
	flags := payload[0]
	pfxLen := payload[1]
	maxLen := payload[2]
	// payload[3] = reserved
	var raw [16]byte
	copy(raw[:], payload[4:20])
	addr := netip.AddrFrom16(raw)
	asn := msb.Uint32(payload[20:24])
	prefix, err := addr.Prefix(int(pfxLen))
	if err != nil {
		return fmt.Errorf("rtr: invalid IPv6 prefix /%d: %w", pfxLen, err)
	}
	if c.Options.OnROA != nil {
		c.Options.OnROA(flags == FlagAnnounce, prefix.Masked(), maxLen, asn)
	}
	return nil
}

func (c *Client) dispatchASPA(h pduHeader, payload []byte) error {
	// NB: ASPA PDUs are only defined for RTR v2; ignore silently for lower versions
	if h.Version < VersionV2 {
		c.Debug().Uint8("version", h.Version).Msg("RTR ignoring ASPA PDU from non-v2 server")
		return nil
	}
	if len(payload) < 4 {
		return fmt.Errorf("rtr: ASPA payload %d < 4", len(payload))
	}
	if (len(payload)-4)%4 != 0 {
		return fmt.Errorf("rtr: ASPA payload not 4-byte aligned: %d", len(payload))
	}
	// NB: per draft-ietf-sidrops-8210bis §6.12, flags is in header byte 2,
	// which is the high byte of h.Session (uint16 from bytes 2-3 of the header).
	flags := byte(h.Session >> 8)
	add := flags&FlagAnnounce != 0
	cas := msb.Uint32(payload[0:4])

	var providers []uint32
	if add {
		// provider ASNs follow the customer ASN, 4 bytes each
		provCount := (len(payload) - 4) / 4
		providers = make([]uint32, provCount)
		for i := range provCount {
			providers[i] = msb.Uint32(payload[4+i*4:])
		}
	}

	if c.Options.OnASPA != nil {
		c.Options.OnASPA(add, cas, providers)
	}
	return nil
}

func (c *Client) dispatchEndOfData(h pduHeader, payload []byte) error {
	// NB: v0 EndOfData is 12 bytes total (payload=4: serial only)
	// v1/v2 EndOfData is 24 bytes total (payload=16: serial + intervals)
	if len(payload) < 4 {
		return fmt.Errorf("rtr: EndOfData payload %d < 4", len(payload))
	}
	serial := msb.Uint32(payload[0:4])

	c.mu.Lock()
	// NB: check for session ID change (server restarted or config changed)
	if c.hasSerial && h.Session != c.sessid {
		c.Warn().
			Uint16("old", c.sessid).
			Uint16("new", h.Session).
			Msg("RTR session ID changed in EndOfData")
	}
	c.serial = serial
	c.sessid = h.Session
	c.hasSerial = true
	sessid := h.Session
	c.mu.Unlock()

	c.Debug().Uint16("sessid", sessid).Uint32("serial", serial).Msg("RTR end of data")

	if c.Options.OnEndOfData != nil {
		c.Options.OnEndOfData(sessid, serial)
	}
	return nil
}
