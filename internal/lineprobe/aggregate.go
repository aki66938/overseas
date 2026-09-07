package lineprobe

import (
	"sort"
	"time"
)

// Aggregate remembers consecutive unsuccessful checks per target. HTTP 403/429
// prove HTTPS reachability only; 5xx is reachable but unhealthy service status.
type Aggregate struct {
	failures map[string]int
	quality  string
}

func (a *Aggregate) Update(results []Result) string {
	if a.failures == nil {
		a.failures = make(map[string]int)
	}
	sustained := 0
	latencies := make([]int64, 0, len(results))
	for _, r := range results {
		if r.Reachable && r.HTTPStatus >= 200 && r.HTTPStatus < 500 {
			a.failures[r.ID] = 0
			latencies = append(latencies, r.LatencyMS)
		} else if a.failures[r.ID] < 3 {
			a.failures[r.ID]++
		}
		if a.failures[r.ID] >= 3 {
			sustained++
		}
	}
	if sustained > len(results)/2 {
		a.quality = "failed"
		return a.quality
	}
	if len(latencies) <= len(results)/2 {
		if a.quality == "" {
			return "unknown"
		}
		return a.quality
	}
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	a.quality = "good"
	if latencies[len(latencies)/2] >= 1000 {
		a.quality = "slow"
	}
	return a.quality
}

const RoundBudget = 5 * time.Second
