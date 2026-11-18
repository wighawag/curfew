//go:build ignore

// goflock takes an exclusive flock(2) on a file the way the curfew daemon
// would, and reports whether it got it. With "hold N" it keeps it for N
// seconds, so a shell flock(1) or lock(1) can be tried against it.
//
//	CGO_ENABLED=0 go build -o /tmp/curfew-spike/goflock docs/spikes/serialise-dhcp-commits-with-one-lock/goflock.go
//
// Usage: goflock <path> try | goflock <path> hold <seconds>
package main

import (
	"fmt"
	"os"
	"strconv"
	"syscall"
	"time"
)

func main() {
	f, err := os.OpenFile(os.Args[1], os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		fmt.Println("open:", err)
		os.Exit(2)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		fmt.Println("go flock: BUSY:", err)
		os.Exit(1)
	}
	fmt.Println("go flock: ACQUIRED")
	if len(os.Args) > 3 && os.Args[2] == "hold" {
		n, _ := strconv.Atoi(os.Args[3])
		time.Sleep(time.Duration(n) * time.Second)
	}
}
