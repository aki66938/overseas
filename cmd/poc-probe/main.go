package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"corp.example/overseas-access-gateway/internal/config"
	"corp.example/overseas-access-gateway/internal/inventory"
)

var snapshot = inventory.Snapshot

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "PREFLIGHT_USAGE: poc-probe preflight --config <path>")
		return 2
	}

	switch args[0] {
	case "preflight":
		return runPreflight(args[1:], stdout, stderr)
	case "inventory":
		return runInventory(args[1:], stdout, stderr)
	default:
		fmt.Fprintln(stderr, "PREFLIGHT_USAGE: poc-probe preflight --config <path>")
		return 2
	}
}

func runPreflight(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("preflight", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configPath := flags.String("config", "", "path to PoC configuration")
	if err := flags.Parse(args); err != nil || *configPath == "" || flags.NArg() != 0 {
		fmt.Fprintln(stderr, "PREFLIGHT_USAGE: poc-probe preflight --config <path>")
		return 2
	}

	if _, err := config.Load(*configPath); err != nil {
		fmt.Fprintf(stderr, "PREFLIGHT_CONFIG_ERROR: %v\n", err)
		return 1
	}

	fmt.Fprintln(stdout, "PREFLIGHT_CONFIG_OK")
	return 0
}

func runInventory(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("inventory", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configPath := flags.String("config", "", "path to PoC configuration")
	outputPath := flags.String("out", "", "path for new JSON evidence")
	if err := flags.Parse(args); err != nil || *configPath == "" || *outputPath == "" || flags.NArg() != 0 {
		fmt.Fprintln(stderr, "INVENTORY_USAGE: poc-probe inventory --config <path> --out <path>")
		return 2
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(stderr, "INVENTORY_CONFIG_ERROR: %v\n", err)
		return 1
	}
	state, err := snapshot(context.Background())
	if err != nil {
		fmt.Fprintf(stderr, "INVENTORY_SNAPSHOT_ERROR: %v\n", err)
		return 1
	}
	if err := inventory.Validate(state, cfg); err != nil {
		fmt.Fprintf(stderr, "INVENTORY_VALIDATION_ERROR: %v\n", err)
		return 1
	}
	if err := writeNewJSON(*outputPath, state); err != nil {
		fmt.Fprintf(stderr, "INVENTORY_OUTPUT_ERROR: %v\n", err)
		return 1
	}

	fmt.Fprintln(stdout, "INVENTORY_OK")
	return 0
}

func writeNewJSON(path string, value any) error {
	contents, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("encode evidence: %w", err)
	}
	contents = append(contents, '\n')

	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create evidence file: %w", err)
	}
	if _, err := file.Write(contents); err != nil {
		_ = file.Close()
		return fmt.Errorf("write evidence file: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close evidence file: %w", err)
	}
	return nil
}
