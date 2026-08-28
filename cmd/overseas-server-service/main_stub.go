//go:build !windows

package main

import (
	"fmt"
	"os"
)

func main() {
	_, _ = fmt.Fprintln(os.Stderr, "overseas-server-service is supported only on Windows")
}
