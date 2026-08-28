//go:build !windows

package runtimeowner

import "os"

func replaceFile(source, destination string) error { return os.Rename(source, destination) }
