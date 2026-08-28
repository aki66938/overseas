package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"corp.example/overseas-access-gateway/internal/accessmodel"
	"gopkg.in/yaml.v3"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "USAGE: access-config <validate-policy|hash-policy> -in <path|->")
		return 2
	}

	switch args[0] {
	case "validate-policy":
		return runValidatePolicy(args[1:], stdin, stdout, stderr)
	case "hash-policy":
		return runHashPolicy(args[1:], stdin, stdout, stderr)
	default:
		fmt.Fprintln(stderr, "USAGE: access-config <validate-policy|hash-policy> -in <path|->")
		return 2
	}
}

func runValidatePolicy(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("validate-policy", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	input := flags.String("in", "", "policy path or - for stdin")
	if err := flags.Parse(args); err != nil || *input == "" || flags.NArg() != 0 {
		fmt.Fprintln(stderr, "USAGE: access-config validate-policy -in <path|->")
		return 2
	}

	policy, err := readPolicy(*input, stdin)
	if err != nil {
		fmt.Fprintf(stderr, "VALIDATE_POLICY_ERROR: %v\n", err)
		return 3
	}
	if err := accessmodel.Validate(policy); err != nil {
		fmt.Fprintf(stderr, "VALIDATE_POLICY_ERROR: %v\n", err)
		return 3
	}
	fmt.Fprintln(stdout, "POLICY_VALID")
	return 0
}

func runHashPolicy(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("hash-policy", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	input := flags.String("in", "", "policy path or - for stdin")
	if err := flags.Parse(args); err != nil || *input == "" || flags.NArg() != 0 {
		fmt.Fprintln(stderr, "USAGE: access-config hash-policy -in <path|->")
		return 2
	}

	policy, err := readPolicy(*input, stdin)
	if err != nil {
		fmt.Fprintf(stderr, "HASH_POLICY_ERROR: %v\n", err)
		return 3
	}
	hash, err := accessmodel.CanonicalSHA256(policy)
	if err != nil {
		fmt.Fprintf(stderr, "HASH_POLICY_ERROR: %v\n", err)
		return 3
	}
	fmt.Fprintln(stdout, hash)
	return 0
}

func readPolicy(path string, stdin io.Reader) (accessmodel.Policy, error) {
	var contents []byte
	var err error
	if path == "-" {
		contents, err = io.ReadAll(stdin)
		if err != nil {
			return accessmodel.Policy{}, fmt.Errorf("read policy: %w", err)
		}
	} else {
		contents, err = os.ReadFile(path)
		if err != nil {
			return accessmodel.Policy{}, fmt.Errorf("read policy: %w", err)
		}
	}

	var policy accessmodel.Policy
	decoder := yaml.NewDecoder(bytes.NewReader(contents))
	decoder.KnownFields(true)
	if err := decoder.Decode(&policy); err != nil {
		return accessmodel.Policy{}, yamlDecodeError(err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return accessmodel.Policy{}, fmt.Errorf("policy must contain exactly one YAML document")
	}
	return policy, nil
}

func yamlDecodeError(err error) error {
	const fieldMarker = "field "
	const notFoundMarker = " not found"

	message := err.Error()
	start := strings.Index(message, fieldMarker)
	if start >= 0 {
		field := message[start+len(fieldMarker):]
		if end := strings.Index(field, notFoundMarker); end >= 0 {
			return fmt.Errorf("policy contains unknown field %s", field[:end])
		}
	}
	return fmt.Errorf("policy YAML is invalid")
}
