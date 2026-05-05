//go:build linux

package httpsnoop_test

import (
	"context"
	"fmt"
	"log"
	"os/signal"
	"syscall"

	"github.com/jamessanford/httpsnoop"
)

// Example output for a process making requests:
//
//	1234 GET https://192.168.100.55:8888/v1/users
//	  Authorization: Bearer XXXX
//	  Accept: application/json
func Example() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	snoop, err := httpsnoop.Init(ctx)
	if err != nil {
		log.Fatal(err)
	}

	pid := 1234
	if err := snoop.Attach(pid); err != nil {
		log.Fatal(err)
	}

	for ev := range snoop.Events() {
		fmt.Printf("%d %s %s\n", ev.PID, ev.Method, ev.URL)
		for k, v := range ev.Headers {
			fmt.Printf("  %s: %s\n", k, v)
		}
	}
}
