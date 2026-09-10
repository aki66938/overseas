//go:build !darwin

package main

import "errors"

func runPlatform([]string) error { return errors.New("installation requires macOS arm64") }
