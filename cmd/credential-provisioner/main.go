package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

const (
	credentialPath     = `C:\ProgramData\RegenBio\OverseasAccess\credential.bin`
	maxCredentialBytes = 64 * 1024
)

type storeMachineFunc func(string, []byte) error

type credentialDocument struct {
	Method    string          `json:"method"`
	Endpoint  string          `json:"endpoint"`
	Password  json.RawMessage `json:"password"`
	ExpiresAt time.Time       `json:"expires_at"`
}

type credentialContract struct {
	Method    string
	Endpoint  string
	ExpiresAt time.Time
}

func runProvisioner(args []string, input io.Reader, inputIsTerminal bool, output, errorOutput io.Writer, store storeMachineFunc) int {
	contract, err := parseCredentialContract(args, time.Now().UTC())
	if err != nil || inputIsTerminal {
		_, _ = fmt.Fprintln(errorOutput, "credential provisioning failed")
		return 2
	}
	contents, err := io.ReadAll(io.LimitReader(input, maxCredentialBytes+1))
	if err != nil || len(contents) > maxCredentialBytes {
		zeroBytes(contents)
		_, _ = fmt.Fprintln(errorOutput, "credential provisioning failed")
		return 1
	}
	if err := provisionCredential(contents, time.Now().UTC(), contract, store); err != nil {
		_, _ = fmt.Fprintln(errorOutput, "credential provisioning failed")
		return 1
	}
	_, _ = fmt.Fprintln(output, "credential provisioned")
	return 0
}

func parseCredentialContract(args []string, now time.Time) (credentialContract, error) {
	if len(args) != 6 || args[0] != "--expected-method" || args[2] != "--expected-endpoint" || args[4] != "--expected-expires-at" {
		return credentialContract{}, errors.New("credential contract is invalid")
	}
	method, endpoint := args[1], args[3]
	host, portText, err := net.SplitHostPort(endpoint)
	port, portErr := strconv.Atoi(portText)
	expires, timeErr := time.Parse(time.RFC3339, args[5])
	if strings.TrimSpace(method) != method || method == "" || len(method) > 128 || host == "" || err != nil || portErr != nil || port < 1 || port > 65535 || timeErr != nil || !expires.After(now) || expires.Format(time.RFC3339) != args[5] {
		return credentialContract{}, errors.New("credential contract is invalid")
	}
	return credentialContract{Method: method, Endpoint: endpoint, ExpiresAt: expires}, nil
}

func provisionCredential(contents []byte, now time.Time, contract credentialContract, store storeMachineFunc) error {
	defer zeroBytes(contents)
	if len(contents) == 0 {
		return errors.New("credential document is invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	var document credentialDocument
	if err := decoder.Decode(&document); err != nil {
		return errors.New("credential document is invalid")
	}
	defer zeroBytes(document.Password)
	var additional any
	if err := decoder.Decode(&additional); !errors.Is(err, io.EOF) {
		return errors.New("credential document is invalid")
	}
	if document.Method != contract.Method || document.Endpoint != contract.Endpoint || !document.ExpiresAt.Equal(contract.ExpiresAt) || len(document.Password) <= 2 || document.Password[0] != '"' || document.Password[len(document.Password)-1] != '"' || bytes.Equal(document.Password, []byte(`""`)) || !document.ExpiresAt.After(now) {
		return errors.New("credential document is invalid")
	}
	if err := store(credentialPath, contents); err != nil {
		return errors.New("credential storage failed")
	}
	return nil
}

func zeroBytes(data []byte) {
	for index := range data {
		data[index] = 0
	}
}
