//go:build windows

package main

import (
	"os"

	"corp.example/overseas-access-gateway/internal/runtimeowner"
	"corp.example/overseas-access-gateway/internal/secret"
)

func main() {
	info, err := os.Stdin.Stat()
	inputIsTerminal := err != nil || info.Mode()&os.ModeCharDevice != 0
	store := func(path string, data []byte) error {
		if err := secret.StoreMachine(path, data); err != nil {
			return err
		}
		return runtimeowner.Record(path)
	}
	os.Exit(runProvisioner(os.Args[1:], os.Stdin, inputIsTerminal, os.Stdout, os.Stderr, store))
}
