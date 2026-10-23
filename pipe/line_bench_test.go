package pipe

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"

	"github.com/bgpfix/bgpfix/msg"
)

// BenchmarkLineTCP measures writing Line output to a loopback TCP connection,
// as eg. bgpipe does with tcp.ReadFrom(line)
func BenchmarkLineTCP(b *testing.B) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer ln.Close()
	done := make(chan int64)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			done <- 0
			return
		}
		n, _ := io.Copy(io.Discard, c)
		done <- n
	}()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		b.Fatal(err)
	}

	p := NewPipe(context.Background())
	p.msgpool = new(sync.Pool)
	l := p.R
	l.Out = make(chan *msg.Msg, 1024)
	go func() {
		for range b.N {
			m := p.GetMsg()
			m.Switch(msg.UPDATE)
			m.Data = []byte{0, 0, 0, 0} // empty UPDATE (EoR), 23 bytes on wire
			l.Out <- m
		}
		close(l.Out)
	}()

	b.ReportAllocs()
	b.ResetTimer()
	conn.(*net.TCPConn).ReadFrom(l)
	conn.Close()
	if n := <-done; n != int64(b.N)*23 {
		b.Fatalf("got %d bytes, want %d", n, b.N*23)
	}
}
