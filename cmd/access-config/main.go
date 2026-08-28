package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"corp.example/overseas-access-gateway/internal/accessmodel"
	"corp.example/overseas-access-gateway/internal/singconfig"
	"gopkg.in/yaml.v3"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, usageLine())
		return 2
	}

	switch args[0] {
	case "validate-policy":
		return runValidatePolicy(args[1:], stdin, stdout, stderr)
	case "hash-policy":
		return runHashPolicy(args[1:], stdin, stdout, stderr)
	case "render-server":
		return runRenderServer(args[1:], stdin, stdout, stderr)
	case "render-client":
		return runRenderClient(args[1:], stdin, stdout, stderr)
	default:
		fmt.Fprintln(stderr, usageLine())
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

func runRenderServer(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("render-server", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	input := flags.String("in", "", "policy path or - for stdin")
	nodeID := flags.String("node", "", "policy node id")
	listen := flags.String("listen", "", "listen IP address")
	upstream := flags.String("upstream", "", "upstream host:port")
	output := flags.String("out", "", "output config path")
	method := flags.String("method", singconfig.DefaultMethod, "Shadowsocks method")
	secretStdin := flags.Bool("secret-stdin", false, "read secret from stdin")
	secretHandle := flags.String("secret-handle", "", "read secret from inherited handle")
	if err := flags.Parse(args); err != nil || *input == "" || *nodeID == "" || *listen == "" || *upstream == "" || *output == "" || flags.NArg() != 0 || !validSecretSource(*secretStdin, *secretHandle) || (*input == "-" && *secretStdin) {
		fmt.Fprintln(stderr, "USAGE: access-config render-server -in <path|-> -node <id> -listen <ip> -upstream <host:port> -out <path> (-secret-stdin|-secret-handle <value>) [-method <name>]")
		return 2
	}

	policy, err := readPolicy(*input, stdin)
	if err != nil {
		fmt.Fprintf(stderr, "RENDER_SERVER_ERROR: %v\n", err)
		return 3
	}
	if err := accessmodel.Validate(policy); err != nil {
		fmt.Fprintf(stderr, "RENDER_SERVER_ERROR: %v\n", err)
		return 3
	}
	node, err := selectNode(policy.Nodes, *nodeID)
	if err != nil {
		fmt.Fprintf(stderr, "RENDER_SERVER_ERROR: %v\n", err)
		return 3
	}
	secret, err := readSecret(*secretStdin, *secretHandle, stdin)
	if err != nil {
		fmt.Fprintf(stderr, "RENDER_SERVER_ERROR: %v\n", err)
		return 3
	}
	config, err := singconfig.RenderServer(singconfig.ServerInput{
		Listen:   *listen,
		Port:     node.Port,
		Method:   *method,
		Password: secret,
		Upstream: *upstream,
	})
	if err != nil {
		fmt.Fprintf(stderr, "RENDER_SERVER_ERROR: %v\n", err)
		return 3
	}
	if err := writeAtomically(*output, config); err != nil {
		fmt.Fprintf(stderr, "RENDER_SERVER_ERROR: %v\n", err)
		return 3
	}
	fmt.Fprintf(stdout, "CONFIG_WRITTEN %s\n", *output)
	fmt.Fprintf(stdout, "APPLY_SERVICE_ONLY_ACL %s\n", *output)
	return 0
}

func runRenderClient(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("render-client", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	input := flags.String("in", "", "policy path or - for stdin")
	nodeID := flags.String("node", "", "policy node id")
	output := flags.String("out", "", "output config path")
	method := flags.String("method", singconfig.DefaultMethod, "Shadowsocks method")
	secretStdin := flags.Bool("secret-stdin", false, "read secret from stdin")
	secretHandle := flags.String("secret-handle", "", "read secret from inherited handle")
	if err := flags.Parse(args); err != nil || *input == "" || *nodeID == "" || *output == "" || flags.NArg() != 0 || !validSecretSource(*secretStdin, *secretHandle) || (*input == "-" && *secretStdin) {
		fmt.Fprintln(stderr, "USAGE: access-config render-client -in <path|-> -node <id> -out <path> (-secret-stdin|-secret-handle <value>) [-method <name>]")
		return 2
	}

	policy, err := readPolicy(*input, stdin)
	if err != nil {
		fmt.Fprintf(stderr, "RENDER_CLIENT_ERROR: %v\n", err)
		return 3
	}
	if err := accessmodel.Validate(policy); err != nil {
		fmt.Fprintf(stderr, "RENDER_CLIENT_ERROR: %v\n", err)
		return 3
	}
	node, err := selectNode(policy.Nodes, *nodeID)
	if err != nil {
		fmt.Fprintf(stderr, "RENDER_CLIENT_ERROR: %v\n", err)
		return 3
	}
	secret, err := readSecret(*secretStdin, *secretHandle, stdin)
	if err != nil {
		fmt.Fprintf(stderr, "RENDER_CLIENT_ERROR: %v\n", err)
		return 3
	}
	config, err := singconfig.RenderClient(singconfig.ClientInput{
		Node:             node,
		CorporateCIDRs:   policy.CorporateCIDRs,
		CorporateDNS:     policy.CorporateDNS,
		InternalSuffixes: policy.InternalSuffixes,
		Method:           *method,
		Password:         secret,
	})
	if err != nil {
		fmt.Fprintf(stderr, "RENDER_CLIENT_ERROR: %v\n", err)
		return 3
	}
	if err := writeAtomically(*output, config); err != nil {
		fmt.Fprintf(stderr, "RENDER_CLIENT_ERROR: %v\n", err)
		return 3
	}
	fmt.Fprintf(stdout, "CONFIG_WRITTEN %s\n", *output)
	fmt.Fprintf(stdout, "APPLY_SERVICE_ONLY_ACL %s\n", *output)
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

func usageLine() string {
	return "USAGE: access-config <validate-policy|hash-policy|render-server|render-client> ..."
}

func validSecretSource(secretStdin bool, secretHandle string) bool {
	if secretStdin {
		return strings.TrimSpace(secretHandle) == ""
	}
	return strings.TrimSpace(secretHandle) != ""
}

func selectNode(nodes []accessmodel.Node, id string) (accessmodel.Node, error) {
	for _, node := range nodes {
		if node.ID == id {
			return node, nil
		}
	}
	return accessmodel.Node{}, fmt.Errorf("node %q was not found in policy", id)
}

func readSecret(secretStdin bool, secretHandle string, stdin io.Reader) (string, error) {
	var data []byte
	var err error
	if secretStdin {
		data, err = io.ReadAll(stdin)
		if err != nil {
			return "", fmt.Errorf("read secret: %w", err)
		}
	} else {
		handleValue, parseErr := strconv.ParseUint(strings.TrimSpace(secretHandle), 0, 64)
		if parseErr != nil {
			return "", fmt.Errorf("secret handle must be an integer: %w", parseErr)
		}
		file := os.NewFile(uintptr(handleValue), "secret-handle")
		if file == nil {
			return "", fmt.Errorf("secret handle is invalid")
		}
		defer file.Close()
		data, err = io.ReadAll(file)
		if err != nil {
			return "", fmt.Errorf("read secret: %w", err)
		}
	}

	secret := strings.TrimSpace(string(data))
	if secret == "" {
		return "", fmt.Errorf("secret must not be empty")
	}
	return secret, nil
}

func writeAtomically(path string, contents []byte) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}

	temp, err := os.CreateTemp(directory, ".access-config-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)

	if _, err := temp.Write(contents); err != nil {
		temp.Close()
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := replaceFile(tempPath, path); err != nil {
		return fmt.Errorf("publish output file: %w", err)
	}
	return nil
}
