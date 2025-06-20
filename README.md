 # BGPFix Golang Library

[![Go Reference](https://pkg.go.dev/badge/github.com/bgpfix/bgpfix.svg)](https://pkg.go.dev/github.com/bgpfix/bgpfix)

A generic-purpose, high-performance Golang library for [bridging the gaps in BGP](https://twitter.com/ACM_IMC2021/status/1445725066403196928).

**For a stand-alone tool, see [bgpipe: a BGP firewall](https://bgpipe.org/).**

# Summary

BGPFix can "fix" or "extend" BGP sessions *in-flight*, possibly adding new features or security layers to proprietary BGP speakers (think big router vendors). The project vision is to allow implementing:
 * bidirectional BGP session to JSON translation, replacing [exabgp](https://github.com/Exa-Networks/exabgp/) for some use-cases,
 * transparent BGP proxy, optionally rewriting and filtering messages in-flight,
 * streaming MRT files to BGP routers, adding the necessary OPEN negotiation beforehand,
 * Flowspec data plane firewalls using [Linux Netfilter](https://netfilter.org/),
 * passive inspection (and storage) of ongoing BGP sessions, like in [tcpdump](https://www.tcpdump.org/),
 * cool new BGP extensions for legacy speakers, eg. [RPKI](https://en.wikipedia.org/wiki/Resource_Public_Key_Infrastructure) and [ASPA](https://www.manrs.org/2023/02/unpacking-the-first-route-leak-prevented-by-aspa/) validation, [Only To Customer (OTC)](https://www.manrs.org/2023/04/there-is-still-hope-for-bgp-route-leak-prevention/) attribute, or even [BGPSec](https://en.wikipedia.org/wiki/BGPsec),
 * protecting from [grave flaws in BGP error handling](https://blog.benjojo.co.uk/post/bgp-path-attributes-grave-error-handling), and possibly other flaws found using [BGP fuzzing projects](https://github.com/Forescout/bgp_boofuzzer)
 * academic research ideas, eg. [Pretty Good BGP](https://www.cs.princeton.edu/~jrex/papers/pgbgp.pdf) or protection against [distributed prefix de-aggregation attacks](https://arxiv.org/abs/2210.10676).

# Idea

The overall idea is presented below. You don't need to use the whole library, eg. you may stick to the basic [BGP message marshal / unmarshal procedures](https://pkg.go.dev/github.com/bgpfix/bgpfix@master/msg).

![bgpfix idea](bgpfix.png)

The above explains the concept of a [Pipe](https://pkg.go.dev/github.com/bgpfix/bgpfix@master/pipe#Pipe): it has two directions used to exchange BGP messages between 2 speakers on the left (L) and right (R) hand side of the picture.

Each [Msg](https://pkg.go.dev/github.com/bgpfix/bgpfix@master/msg#Msg) sent to the In channel of a particular direction will go through a set of *callbacks* (think "plugins") configured in the [pipe Options](https://pkg.go.dev/github.com/bgpfix/bgpfix@master/pipe#Options). Each callback can read, write, modify, synthesize, or drop messages before they reach the Out channel. In addition to BGP messages, callbacks may emit [Events](https://pkg.go.dev/github.com/bgpfix/bgpfix@master/pipe#Event) - such as [the standard events of the Pipe](https://pkg.go.dev/github.com/bgpfix/bgpfix@master/pipe#pkg-variables) - which [event handlers may subscribe to](https://pkg.go.dev/github.com/bgpfix/bgpfix@master/pipe#Options.OnEvent) in the pipe Options.

# Example

A basic example on how to establish a BGP session with a router, and print all messages as JSON to stdout:

```go
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"

	"github.com/bgpfix/bgpfix/msg"
	"github.com/bgpfix/bgpfix/pipe"
	"github.com/bgpfix/bgpfix/speaker"
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

	// create a Pipe, add callback and event handlers
	p := pipe.NewPipe(context.Background())
	p.OnMsg(print, dir.DIR_LR) // call print() on every message in any direction
	p.OnEvent(event)           // call event() on any pipe event

	// L side: a TCP target, sending to R
	conn, err := net.Dial("tcp", flag.Arg(0)) // assumes a ":179" suffix
	if err != nil {
		panic(err)
	}

	// R side: a local speaker, sending to L
	spk := speaker.NewSpeaker(context.Background())
	spk.Options.Passive = !*opt_active
	spk.Options.LocalASN = *opt_asn
	spk.Options.LocalHoldTime = *opt_hold
	spk.Options.LocalId = netip.MustParseAddr(*opt_id)
	spk.Attach(p, dir.DIR_L)

	// copy from conn -> R
	go func() {
		io.Copy(p.R, conn)
		p.Stop()
	}()

	// copy from L -> conn
	go func() {
		io.Copy(conn, p.L)
		p.Stop()
	}()

	// start and wait till all processing is done
	p.Start()
	p.Wait()
}

func print(m *msg.Msg) bool {
	os.Stdout.Write(m.GetJSON())
	return true
}

func event(ev *pipe.Event) bool {
	switch ev.Type {
	case pipe.EVENT_ESTABLISHED:
		fmt.Printf("session established, capabilities: %s\n", ev.Pipe.Caps.String())
	}
	return true
}
```

# JSON

BGPFix has full, *bi-directional* BGP to JSON translation support.

For example, below we use [bgpipe](https://bgpipe.org) to connect to the Flowspec version of the great [BGP Blackholing project](https://lukasz.bromirski.net/bgp-fs-blackholing/) by [@LukaszBromirski](https://twitter.com/LukaszBromirski).

```json
$ bgpipe --log disabled --stdout \
	-- speaker --active --asn 65055 \
	-- connect 85.232.240.180 | jq .
[
  "R",
  1,
  "2024-11-28T13:06:47.574",
  -1,
  "OPEN",
  {
    "bgp": 4,
    "asn": 65055,
    "id": "0.0.0.1",
    "hold": 90,
    "caps": {
      "MP": [
        "IPV4/UNICAST",
        "IPV4/FLOWSPEC",
        "IPV6/UNICAST",
        "IPV6/FLOWSPEC"
      ],
      "ROUTE_REFRESH": true,
      "EXTENDED_MESSAGE": true,
      "AS4": 65055
    }
  },
  {}
]
[
  "L",
  1,
  "2024-11-28T13:06:49.598",
  56,
  "OPEN",
  {
    "bgp": 4,
    "asn": 65055,
    "id": "85.232.240.180",
    "hold": 7200,
    "caps": {
      "MP": [
        "IPV4/FLOWSPEC"
      ],
      "ROUTE_REFRESH": true,
      "EXTENDED_NEXTHOP": [
        "IPV4/UNICAST/IPV6",
        "IPV4/MULTICAST/IPV6",
        "IPV4/MPLS_VPN/IPV6"
      ],
      "AS4": 65055,
      "PRE_ROUTE_REFRESH": true
    }
  },
  {}
]
[
  "L",
  2,
  "2024-11-28T13:06:49.598",
  0,
  "KEEPALIVE",
  null,
  {}
]
[
  "R",
  2,
  "2024-11-28T13:06:49.598",
  0,
  "KEEPALIVE",
  null,
  {}
]
[
  "L",
  3,
  "2024-11-28T13:06:54.622",
  316,
  "UPDATE",
  {
    "attrs": {
      "ORIGIN": {
        "flags": "T",
        "value": "IGP"
      },
      "ASPATH": {
        "flags": "T",
        "value": []
      },
      "LOCALPREF": {
        "flags": "T",
        "value": 100
      },
      "ORIGINATOR": {
        "flags": "O",
        "value": "85.232.240.170"
      },
      "CLUSTER_LIST": {
        "flags": "O",
        "value": [
          "85.232.240.180"
        ]
      },
      "MP_REACH": {
        "flags": "OX",
        "value": {
          "af": "IPV4/FLOWSPEC",
          "nexthop": "192.0.2.1",
          "rules": [
            {
              "SRC": "2.59.255.53/32",
              "PROTO": [
                {
                  "op": "==",
                  "val": 6
                }
              ],
              "PORT_DST": [
                {
                  "op": "==",
                  "val": 25
                }
              ]
            },
            {
              "SRC": "5.29.8.251/32",
              "PROTO": [
                {
                  "op": "==",
                  "val": 6
                }
              ],
              "PORT_DST": [
                {
                  "op": "==",
                  "val": 25
                }
              ]
            },
// *** ... cut many, many lines ... ***
            {
              "SRC": "220.158.197.0/24",
              "PROTO": [
                {
                  "op": "==",
                  "val": 6
                }
              ],
              "PORT_DST": [
                {
                  "op": "==",
                  "val": 25
                }
              ]
            }
          ]
        }
      },
      "EXT_COMMUNITY": {
        "flags": "OT",
        "value": [
          {
            "type": "FLOW_RATE_BYTES",
            "value": 0
          }
        ]
      }
    }
  },
  {}
]
[
  "L",
  9,
  "2024-11-28T13:06:54.708",
  10,
  "UPDATE",
  {
    "attrs": {
      "MP_UNREACH": {
        "flags": "O",
        "value": {
          "af": "IPV4/FLOWSPEC",
          "rules": []
        }
      }
    }
  },
  {}
]
^C
```

# BGP features

RFCs:
 * [RFC1997 BGP Communities Attribute](https://datatracker.ietf.org/doc/html/rfc1997)
 * [RFC2918 Route Refresh Capability for BGP-4](https://datatracker.ietf.org/doc/html/rfc2918)
 * [RFC4360 BGP Extended Communities Attribute](https://datatracker.ietf.org/doc/html/rfc4360)
 * [RFC4271 A Border Gateway Protocol 4 (BGP-4)](https://datatracker.ietf.org/doc/html/rfc4271)
 * [RFC4456 BGP Route Reflection: An Alternative to Full Mesh Internal BGP (IBGP)](https://datatracker.ietf.org/doc/html/rfc4456)
 * [RFC4760 Multiprotocol Extensions for BGP-4](https://datatracker.ietf.org/doc/html/rfc4760)
 * [RFC5492 Capabilities Advertisement with BGP-4](https://datatracker.ietf.org/doc/html/rfc5492)
 * [RFC5668 4-Octet AS Specific BGP Extended Community](https://datatracker.ietf.org/doc/html/rfc5668)
 * [RFC6793 BGP Support for Four-Octet Autonomous System (AS) Number Space](https://datatracker.ietf.org/doc/html/rfc6793)
 * [RFC6396 Multi-Threaded Routing Toolkit (MRT) Routing Information Export Format](https://datatracker.ietf.org/doc/html/rfc6396)
 * [RFC7911 Advertisement of Multiple Paths in BGP](https://datatracker.ietf.org/doc/html/rfc7911)
 * [RFC8092 BGP Large Communities Attribute](https://datatracker.ietf.org/doc/html/rfc8092)
 * [RFC8654 Extended Message Support for BGP](https://datatracker.ietf.org/doc/html/rfc8654)
 * [RFC8950 Advertising IPv4 Network Layer Reachability Information (NLRI) with an IPv6 Next Hop](https://datatracker.ietf.org/doc/html/rfc8950)
 * [RFC8955 Dissemination of Flow Specification Rules](https://datatracker.ietf.org/doc/html/rfc8955)
 * [RFC8956 Dissemination of Flow Specification Rules for IPv6](https://datatracker.ietf.org/doc/html/rfc8956)
 * [RFC9072 Extended Optional Parameters Length for BGP OPEN Message](https://datatracker.ietf.org/doc/html/rfc9072)

Drafts:
 * [draft-simpson-idr-flowspec-redirect: BGP Flow-Spec Extended Community for Traffic Redirect to IP Next Hop](https://datatracker.ietf.org/doc/html/draft-simpson-idr-flowspec-redirect-02)
 * [draft-walton-bgp-hostname-capability-02: Hostname Capability for BGP](https://datatracker.ietf.org/doc/html/draft-walton-bgp-hostname-capability-02)

*Note: some of the above correspond to partial or work-in-progress support.*

# Alternatives

If you're interested in bgpfix, you might also want to see:
 * [exabgp](https://github.com/Exa-Networks/exabgp/)
 * [corebgp](https://github.com/jwhited/corebgp)
 * [xBGP](https://www.usenix.org/conference/nsdi23/presentation/wirtgen)
 * [RouteNormalizer](https://web.eecs.umich.edu/~zmao/Papers/RouteNormalizer.pdf)
 * [BGPKIT](https://bgpkit.com/)

# Author

Pawel Foremski [@pforemski](https://twitter.com/pforemski) 2023-2025
