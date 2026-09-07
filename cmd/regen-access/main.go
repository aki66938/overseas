package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"time"

	"corp.example/overseas-access-gateway/internal/agent"
	"corp.example/overseas-access-gateway/internal/clientapi"
	"corp.example/overseas-access-gateway/internal/localapi"
)

type administratorClient interface {
	DiagnosticEnableV1(context.Context, int) error
}

type connectionClient interface {
	ConnectV1(context.Context) (localapi.Status, error)
	DisconnectV1(context.Context) (localapi.Status, error)
	StatusDetailsV1(context.Context) (localapi.Response, error)
	ProbeV1(context.Context) (localapi.Response, error)
}

func main() { os.Exit(run(os.Args[1:], clientapi.New(), os.Stdout)) }

func run(args []string, client administratorClient, out io.Writer) int {
	return runAt(args, client, out, time.Now())
}

func runAt(args []string, client administratorClient, out io.Writer, now time.Time) int {
	if len(args) == 1 {
		if c, ok := client.(connectionClient); ok {
			ctx, cancel := context.WithTimeout(context.Background(), agent.PipeTimeoutForAction(args[0]))
			defer cancel()
			var response localapi.Response
			var err error
			switch args[0] {
			case "connect":
				response.Status, err = c.ConnectV1(ctx)
			case "disconnect":
				response.Status, err = c.DisconnectV1(ctx)
			case "status":
				response, err = c.StatusDetailsV1(ctx)
			case "probe":
				response, err = c.ProbeV1(ctx)
			default:
				return usage(out)
			}
			if err != nil {
				return commandError(out, err)
			}
			fmt.Fprintf(out, "State: %s\nQuality: %s\n", response.Status.State, response.Status.Quality)
			if connectedAt, parseErr := time.Parse(time.RFC3339, response.Status.ConnectedAt); parseErr == nil && !connectedAt.After(now) {
				fmt.Fprintf(out, "Connected: %s\n", now.Sub(connectedAt).Truncate(time.Second))
			}
			for _, result := range response.ProbeResults {
				label := result.ID
				if response.ProbeHistorical {
					label += " (previous)"
				}
				if result.Reachable {
					fmt.Fprintf(out, "%s: %d ms\n", label, result.LatencyMS)
				} else if result.ErrorCode != "" {
					fmt.Fprintf(out, "%s: %s\n", label, result.ErrorCode)
				} else {
					fmt.Fprintf(out, "%s: unavailable\n", label)
				}
			}
			if response.Status.ErrorCode != "" {
				fmt.Fprintf(out, "Error: %s\n", response.Status.ErrorCode)
				return 1
			}
			if response.Status.State == localapi.StateNeedsAction {
				return 1
			}
			return 0
		}
	}
	if len(args) != 2 || args[0] != "diagnostic-enable" {
		return usage(out)
	}
	minutes, err := strconv.Atoi(args[1])
	if err != nil || (minutes != 15 && minutes != 30 && minutes != 60) {
		fmt.Fprintln(out, "Diagnostic duration must be 15, 30, or 60 minutes.")
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.DiagnosticEnableV1(ctx, minutes); err != nil {
		return commandError(out, err)
	}
	fmt.Fprintf(out, "Diagnostics enabled for %d minutes; expiry or service restart turns collection off.\n", minutes)
	return 0
}

func usage(out io.Writer) int {
	fmt.Fprintln(out, "Usage: regen-access <connect|disconnect|status|probe>\n       regen-access diagnostic-enable <15|30|60> (run as administrator)")
	return 2
}

func commandError(out io.Writer, err error) int {
	if errors.Is(err, clientapi.ErrServiceUnavailable) {
		fmt.Fprintln(out, "Service unavailable.")
	} else {
		fmt.Fprintln(out, "Request failed.")
	}
	return 1
}
