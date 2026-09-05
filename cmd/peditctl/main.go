// peditctl is the terminal-side companion to peditagentd's socket approver:
// run it in a real terminal on the "home" host and it waits for approval
// requests, shows them to you, and -- on approval -- runs the resolved
// profile command right there in its own controlling terminal (needed for
// e.g. vim, which a headless background daemon has no TTY to attach to).
package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"time"

	"pedit/internal/approve"
	"pedit/internal/wire"
)

func main() {
	sock := os.Getenv("PEDIT_CONTROL_SOCKET")
	if len(os.Args) > 1 {
		sock = os.Args[1]
	}
	if sock == "" {
		fmt.Fprintln(os.Stderr, "usage: peditctl <control-socket-path>  (or set PEDIT_CONTROL_SOCKET)")
		os.Exit(2)
	}
	fmt.Println("pedit: waiting for approval requests on", sock, "(Ctrl-C to stop)")
	for {
		conn, err := net.DialTimeout("unix", sock, 3*time.Second)
		if err != nil {
			time.Sleep(1 * time.Second)
			continue
		}
		handleOne(conn)
	}
}

func handleOne(conn net.Conn) {
	defer conn.Close()
	for {
		frame, err := wire.ReadFrame(conn)
		if err != nil {
			return // peditagentd closed it because nothing was pending; just retry
		}
		rd := wire.NewReader(frame)
		kind, err := rd.Byte()
		if err != nil {
			return
		}
		switch kind {
		case approve.CtlAsk:
			// Approval now happens BEFORE any content is transferred, so
			// there is no file to describe yet -- and nothing has been sent
			// if you decline. The question is "did I start this?".
			profile, _ := rd.String()
			filename, _ := rd.String()
			origin, _ := rd.String()
			size, _ := rd.Uint32()
			// Direction is read last so an older peditagentd, which does not
			// send it, degrades to the upload wording rather than failing.
			dir, _ := rd.String()

			header, what, sizeNote := describe(dir, size)
			fmt.Printf("\n--- %s ---\n", header)
			fmt.Printf("  profile: %s\n  file:    %s\n  from:    %s (self-reported, unverified)\n"+
				"  what:    %s\n  size:    %s\n", profile, filename, origin, what, sizeNote)
			fmt.Print("accept? [y/N] ")
			var ans string
			fmt.Scanln(&ans)
			if ans != "y" && ans != "Y" && ans != "yes" {
				_ = wire.WriteFrame(conn, []byte{0})
				fmt.Println("declined; nothing was transferred.")
				return
			}
			if err := wire.WriteFrame(conn, []byte{1}); err != nil {
				return
			}
			// Stay on this connection: the run request follows once the
			// content has arrived.

		case approve.CtlRun:
			cmdLine, _ := rd.String()
			fmt.Printf("  running: %s\n", cmdLine)
			cmd := exec.Command("/bin/sh", "-c", cmdLine)
			cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
			runErr := cmd.Run()

			buf := new(wire.Buffer)
			if runErr != nil {
				if _, isExit := runErr.(*exec.ExitError); !isExit {
					buf.Byte(2).String(fmt.Sprintf("failed to run command: %v", runErr))
					_ = wire.WriteFrame(conn, buf.Out())
					fmt.Fprintln(os.Stderr, "pedit:", runErr)
					return
				}
				fmt.Fprintln(os.Stderr, "pedit: command exited nonzero:", runErr)
			}
			buf.Byte(1)
			_ = wire.WriteFrame(conn, buf.Out())
			fmt.Println("done, result sent back.")
			return

		default:
			return
		}
	}
}

// describe turns the direction into prompt wording. Which way the bytes go
// is the whole substance of the decision -- "a file is arriving here" and
// "a file is leaving here for whoever asked" are not the same thing to
// approve -- so it gets its own line rather than being left implicit in a
// profile name.
func describe(dir string, size uint32) (header, what, sizeNote string) {
	switch dir {
	case approve.DirDown:
		return "pedit DOWNLOAD request (a file leaves this host)",
			"the remote host is asking THIS machine for a file",
			fmt.Sprintf("%d bytes would be sent to it", size)
	case approve.DirList:
		return "pedit LISTING request (filenames leave this host)",
			"the remote host is asking what is in your transfer directory",
			"names and sizes only, no file contents"
	default:
		return "pedit transfer request (a file arrives here)",
			"the remote host is sending a file to THIS machine",
			fmt.Sprintf("%d bytes (not yet transferred)", size)
	}
}
