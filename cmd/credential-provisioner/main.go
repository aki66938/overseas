package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	Password  json.RawMessage `json:"password"`
	ExpiresAt time.Time       `json:"expires_at"`
}

func runProvisioner(args []string, input io.Reader, inputIsTerminal bool, output, errorOutput io.Writer, store storeMachineFunc) int {
	if len(args) != 0 || inputIsTerminal {
		_, _ = fmt.Fprintln(errorOutput, "credential provisioning failed")
		return 2
	}
	contents, err := io.ReadAll(io.LimitReader(input, maxCredentialBytes+1))
	if err != nil || len(contents) > maxCredentialBytes {
		zeroBytes(contents)
		_, _ = fmt.Fprintln(errorOutput, "credential provisioning failed")
		return 1
	}
	if err := provisionCredential(contents, time.Now().UTC(), store); err != nil {
		_, _ = fmt.Fprintln(errorOutput, "credential provisioning failed")
		return 1
	}
	_, _ = fmt.Fprintln(output, "credential provisioned")
	return 0
}

func provisionCredential(contents []byte, now time.Time, store storeMachineFunc) error {
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
	if strings.TrimSpace(document.Method) == "" || len(document.Method) > 128 || len(document.Password) <= 2 || document.Password[0] != '"' || document.Password[len(document.Password)-1] != '"' || bytes.Equal(document.Password, []byte(`""`)) || !document.ExpiresAt.After(now) {
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
