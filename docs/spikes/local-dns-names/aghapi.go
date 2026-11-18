//go:build ignore

// aghapi makes one authenticated call to AdGuard Home's REST API and prints
// the status and body. The test image's wget is uclient-fetch, which fails
// these requests outright (ADR 0010), and the image has no curl.
//
//	CGO_ENABLED=0 go build -o /tmp/curfew-spike/aghapi docs/spikes/local-dns-names/aghapi.go
//
// Usage: aghapi <GET|POST> <path> [json-body]
package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: aghapi <GET|POST> <path> [json]")
		os.Exit(2)
	}
	var body io.Reader
	if len(os.Args) > 3 {
		body = strings.NewReader(os.Args[3])
	}
	req, err := http.NewRequest(os.Args[1], "http://127.0.0.1:3000"+os.Args[2], body)
	if err != nil {
		panic(err)
	}
	req.SetBasicAuth("parent", "hunter2")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Println("ERROR", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	fmt.Printf("[HTTP %d] %s\n", resp.StatusCode, strings.TrimSpace(string(b)))
}
