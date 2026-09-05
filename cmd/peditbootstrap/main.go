// peditbootstrap prints the string you paste on a remote host to fetch and
// source pedit.sh over the forwarded ssh-agent socket.
//
// It takes no arguments. There is one string, and it works on any host:
// it carries every socket client (socat, perl, python3, nc) and tries each
// until one speaks to the agent socket, then fetches a small loader from
// peditagentd, which works out the host's architecture and pulls the real
// script. Everything long or version-specific lives in the loader -- served
// by the daemon, never in your clipboard.
//
// -readable prints the same command decoded, for reading before pasting an
// opaque blob into a shell.
package main

import (
	"flag"
	"fmt"

	"pedit/internal/bootstrap"
)

func main() {
	readable := flag.Bool("readable", false,
		"print the plain command instead of the paste-hardened encoded form")
	flag.Parse()

	if *readable {
		fmt.Println(bootstrap.OneLinerReadable())
		return
	}
	fmt.Println(bootstrap.OneLiner())
}
