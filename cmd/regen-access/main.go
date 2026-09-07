package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"strconv"
	"time"

	"corp.example/overseas-access-gateway/internal/clientapi"
)

type administratorClient interface {
	DiagnosticEnableV1(context.Context, int) error
}

func main() { os.Exit(run(os.Args[1:], clientapi.New(), os.Stdout)) }

func run(args []string, client administratorClient, out io.Writer) int {
	if len(args) != 2 || args[0] != "diagnostic-enable" {
		fmt.Fprintln(out, "Usage: regen-access diagnostic-enable <15|30|60> (run as administrator)")
		return 2
	}
	minutes, err := strconv.Atoi(args[1])
	if err != nil || (minutes != 15 && minutes != 30 && minutes != 60) {
		fmt.Fprintln(out, "Diagnostic duration must be 15, 30, or 60 minutes.")
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.DiagnosticEnableV1(ctx, minutes); err != nil {
		fmt.Fprintf(out, "Could not enable diagnostics: %v\n", err)
		return 1
	}
	fmt.Fprintf(out, "Diagnostics enabled for %d minutes; expiry or service restart turns collection off.\n", minutes)
	return 0
}
