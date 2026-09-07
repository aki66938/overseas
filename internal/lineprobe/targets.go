// Package lineprobe measures HTTPS first-response latency, not bandwidth or
// account/AI-feature availability. Its scheduler only probes the fixed targets.
package lineprobe

type Target struct{ ID, URL string }

func Targets() []Target {
	return []Target{
		{"google", "https://www.google.com/"},
		{"pinterest", "https://www.pinterest.com/"},
		{"gemini", "https://gemini.google.com/"},
		{"chatgpt", "https://chatgpt.com/"},
		{"claude", "https://claude.ai/"},
	}
}
