//go:build live

package rtr

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

// TestLive_Cloudflare connects to Cloudflare's public RTR server and validates
// that the client can receive a full ROA cache (and ASPA if server supports v2).
//
// Run with: go test -tags live -run TestLive_Cloudflare -v -timeout 120s ./rtr/
func TestLive_Cloudflare(t *testing.T) {
	l := zerolog.New(zerolog.NewTestWriter(t)).With().Timestamp().Logger()

	var roaCount atomic.Int64
	var aspaCount atomic.Int64
	cacheReady := make(chan struct{})
	var cacheReadyOnce sync.Once

	c := NewClient(&Options{
		Logger:  &l,
		Version: VersionAuto,
		OnROA: func(add bool, _ netip.Prefix, _ uint8, _ uint32) {
			if add {
				roaCount.Add(1)
			}
		},
		OnASPA: func(add bool, _ uint32, _ []uint32) {
			if add {
				aspaCount.Add(1)
			}
		},
		OnEndOfData: func(sessid uint16, serial uint32) {
			t.Logf("cache ready: sessid=%d serial=%d roas=%d aspas=%d",
				sessid, serial, roaCount.Load(), aspaCount.Load())
			cacheReadyOnce.Do(func() { close(cacheReady) })
		},
		OnError: func(code uint16, text string) {
			t.Logf("server error %d: %s", code, text)
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	conn, err := net.DialTimeout("tcp", "rtr.rpki.cloudflare.com:8282", 15*time.Second)
	require.NoError(t, err, "failed to connect to Cloudflare RTR server")

	runDone := make(chan error, 1)
	go func() { runDone <- c.Run(ctx, conn) }()

	select {
	case <-cacheReady:
		// cache received successfully
	case err := <-runDone:
		t.Fatalf("Run exited before cache was ready: %v", err)
	case <-ctx.Done():
		t.Fatal("timeout waiting for full ROA cache")
	}

	cancel()
	<-runDone

	roas := roaCount.Load()
	aspas := aspaCount.Load()
	t.Logf("received %d ROAs, %d ASPAs, protocol version: %d", roas, aspas, c.Version())
	require.Greater(t, roas, int64(100_000), "expected at least 100k ROAs from Cloudflare")
}
