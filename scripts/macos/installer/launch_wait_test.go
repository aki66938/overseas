package main

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestAwaitUnregisteredTransitionTimeoutAndUnknownError(t *testing.T) {
	for _, kind := range []string{"transition", "timeout", "unknown"} {
		t.Run(kind, func(t *testing.T) {
			now := time.Unix(1, 0)
			calls := 0
			unknown := errors.New("launchd query failed")
			err := awaitUnregistered(time.Second, func() time.Time { return now }, func(d time.Duration) { now = now.Add(d) }, func(budget time.Duration) (bool, error) {
				calls++
				if budget <= 0 || budget > time.Second {
					t.Fatal("unbounded query", budget)
				}
				if kind == "unknown" {
					return false, unknown
				}
				return kind == "timeout" || calls < 3, nil
			})
			switch kind {
			case "transition":
				if err != nil || calls != 3 {
					t.Fatal(calls, err)
				}
			case "timeout":
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatal(err)
				}
			case "unknown":
				if !errors.Is(err, unknown) || calls != 1 {
					t.Fatal(calls, err)
				}
			}
		})
	}
}
