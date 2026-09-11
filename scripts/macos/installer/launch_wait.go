package main

import (
	"context"
	"time"
)

func awaitUnregistered(timeout time.Duration, now func() time.Time, sleep func(time.Duration), query func(time.Duration) (bool, error)) error {
	deadline := now().Add(timeout)
	for {
		remaining := deadline.Sub(now())
		if remaining <= 0 {
			return context.DeadlineExceeded
		}
		present, err := query(min(remaining, time.Second))
		if err != nil {
			return err
		}
		if !present {
			return nil
		}
		remaining = deadline.Sub(now())
		if remaining <= 0 {
			return context.DeadlineExceeded
		}
		sleep(min(100*time.Millisecond, remaining))
	}
}
