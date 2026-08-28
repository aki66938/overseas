//go:build windows

package main

import (
	"os"

	"corp.example/overseas-access-gateway/internal/secret"
)

func main() {
	info, err := os.Stdin.Stat()
	inputIsTerminal := err != nil || info.Mode()&os.ModeCharDevice != 0
	os.Exit(runProvisioner(os.Args[1:], os.Stdin, inputIsTerminal, os.Stdout, os.Stderr, secret.StoreMachine))
}
