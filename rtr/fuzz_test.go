package rtr

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

// streamConn feeds a fixed byte stream to the client and discards its writes.
type streamConn struct{ r io.Reader }

func (c *streamConn) Read(p []byte) (int, error)         { return c.r.Read(p) }
func (c *streamConn) Write(p []byte) (int, error)        { return len(p), nil }
func (c *streamConn) Close() error                       { return nil }
func (c *streamConn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (c *streamConn) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (c *streamConn) SetDeadline(_ time.Time) error      { return nil }
func (c *streamConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *streamConn) SetWriteDeadline(_ time.Time) error { return nil }

// FuzzRtrClient feeds arbitrary server->client byte streams to Client.Run,
// over two consecutive connections, for each protocol version setting.
func FuzzRtrClient(f *testing.F) {
	cat := func(parts ...[]byte) []byte { return bytes.Join(parts, nil) }
	f.Add(cat(buildCacheResponse(2, 1),
		buildIPv4Prefix(2, 1, 24, 24, [4]byte{192, 0, 2, 0}, 65000),
		buildIPv6Prefix(2, 1, 32, 48, [16]byte{0x20, 0x01, 0x0d, 0xb8}, 65001),
		buildASPA(2, true, 65000, []uint32{65001, 65002}),
		buildASPA(2, false, 65000, nil),
		buildEndOfData(2, 1, 7, 3600, 600, 7200)))
	f.Add(cat(buildCacheResponse(0, 9), buildIPv4Prefix(0, 1, 8, 8, [4]byte{10}, 1), buildEndOfData(0, 9, 1, 0, 0, 0)))
	f.Add(cat(buildSerialNotify(1, 1, 5), buildCacheReset(1), buildErrorReport(1, ErrUnsupVersion, "no")))
	f.Add(cat(buildErrorReport(2, ErrCorruptData, "bad"), buildHeader(1, PDURouterKey, 0, 8)))
	f.Add(buildHeader(2, PDUAspa, 0x0100, 0xffffffff))

	versions := []byte{VersionAuto, VersionV0, VersionV1, VersionV2}
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, v := range versions {
			c := NewClient(&Options{
				Version: v,
				OnROA: func(add bool, p netip.Prefix, maxLen uint8, asn uint32) {
					if !p.IsValid() || p != p.Masked() {
						t.Fatalf("bad prefix %v", p)
					}
				},
				OnASPA:       func(add bool, cas uint32, providers []uint32) {},
				OnEndOfData:  func(sessid uint16, serial uint32) {},
				OnCacheReset: func() {},
				OnError:      func(code uint16, text string) {},
			})
			for range 2 {
				c.Run(context.Background(), &streamConn{r: bytes.NewReader(data)})
				c.SendSerial()
			}
		}
	})
}
