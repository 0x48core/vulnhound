// Command vulnhound scans software for known vulnerabilities.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
)

// Exit codes. CI pipelines rely on these staying stable.
const (
	exitOK       = 0
	exitFindings = 1 // findings at or above --fail-on
	exitError    = 2
)

// errFindings signals that the scan succeeded but policy failed.
var errFindings = errors.New("vulnerabilities found at or above the --fail-on threshold")

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	err := newRootCmd().ExecuteContext(ctx)
	switch {
	case err == nil:
		os.Exit(exitOK)
	case errors.Is(err, errFindings):
		fmt.Fprintln(os.Stderr, "vulnhound:", err)
		os.Exit(exitFindings)
	default:
		fmt.Fprintln(os.Stderr, "vulnhound:", err)
		os.Exit(exitError)
	}
}
