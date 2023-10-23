/*
 * a basic example for bgpfix usage
 */
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"

	"github.com/bgpfix/bgpfix/msg"
	"github.com/bgpfix/bgpfix/pipe"
	"github.com/bgpfix/bgpfix/speaker"
	"github.com/bgpfix/bgpfix/util"
)

var (
	opt_active = flag.Bool("active", false, "send OPEN first")
	opt_asn    = flag.Int("asn", 65055, "local ASN number")
	opt_hold   = flag.Int("hold", 60, "local hold timer")
	opt_id     = flag.String("id", "1.1.1.1", "local Id (must be IPv4 address)")
)

func main() {
	// parse flags
	flag.Parse()
	if flag.NArg() == 0 {
		fmt.Printf("usage: bgpfix [OPTIONS] <target:port>\n")
		os.Exit(1)
	}

	// create a Pipe, add our callback and event handlers
	p := pipe.NewPipe(context.Background())
	p.Options.OnMsg(print, msg.DST_LR) // call print() on every message in both directions
	p.Options.OnEvent(event)           // call event() on any pipe event

	// L side: a TCP target
	conn, err := net.Dial("tcp", flag.Arg(0)) // assumes a ":179" suffix
	if err != nil {
		panic(err)
	}

	// R side: a local speaker
	spk := speaker.NewSpeaker(context.Background())
	spk.Options.Passive = !*opt_active
	spk.Options.LocalASN = *opt_asn
	spk.Options.LocalHoldTime = *opt_hold
	spk.Options.LocalId = netip.MustParseAddr(*opt_id)
	spk.Attach(p, msg.DST_L)

	// run a copy util between p and conn
	util.CopyThrough(p, conn, nil)
}

func print(m *msg.Msg) pipe.Action {
	fmt.Printf("%s\n", m.ToJSON(nil))
	return 0
}

func event(ev *pipe.Event) bool {
	switch ev.Type {
	case pipe.EVENT_ESTABLISHED:
		fmt.Printf("session established, capabilities: %s", ev.Pipe.Caps.ToJSON(nil))
	}
	return true
}
