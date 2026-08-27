package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"corp.example/overseas-access-gateway/internal/config"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "preflight" {
		fmt.Fprintln(stderr, "PREFLIGHT_USAGE: poc-probe preflight --config <path>")
		return 2
	}

	flags := flag.NewFlagSet("preflight", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configPath := flags.String("config", "", "path to PoC configuration")
	if err := flags.Parse(args[1:]); err != nil || *configPath == "" || flags.NArg() != 0 {
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
