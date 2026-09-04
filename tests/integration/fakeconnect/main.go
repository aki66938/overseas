// fakeconnect is a deterministic child process used by Windows supervisor tests.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"syscall"
	"time"
)

type config struct {
	Mode          string `json:"mode"`
	ReadyFile     string `json:"ready_file"`
	ChildPIDFile  string `json:"child_pid_file"`
	StartedFile   string `json:"started_file"`
	EscapedFile   string `json:"escaped_file"`
	Secret        string `json:"secret"`
	SuppressReady bool   `json:"suppress_ready"`
	LogRepeat     int    `json:"log_repeat"`
}

func main() {
	if len(os.Args) != 4 || os.Args[1] != "run" || os.Args[2] != "-c" {
		fmt.Fprintln(os.Stderr, "expected: run -c <config>")
		os.Exit(64)
	}
	data, err := os.ReadFile(os.Args[3])
	if err != nil {
		fmt.Fprintln(os.Stderr, "read config")
		os.Exit(65)
	}
	var cfg config
	if err := json.Unmarshal(data, &cfg); err != nil {
		fmt.Fprintln(os.Stderr, "parse config")
		os.Exit(65)
	}

	switch cfg.Mode {
	case "ready":
		markReady(cfg)
		waitForStop()
	case "exit-before-ready":
		os.Exit(23)
	case "hang-on-stop":
		interrupt := make(chan os.Signal, 1)
		signal.Notify(interrupt, os.Interrupt)
		go func() {
			for range interrupt {
			}
		}()
		if cfg.ChildPIDFile != "" && os.Getenv("FAKECONNECT_CHILD") != "1" {
			child := exec.Command(os.Args[0], "run", "-c", os.Args[3])
			child.Env = append(os.Environ(), "FAKECONNECT_CHILD=1")
			if err := child.Start(); err != nil {
				os.Exit(66)
			}
			if err := os.WriteFile(cfg.ChildPIDFile, []byte(strconv.Itoa(child.Process.Pid)), 0o600); err != nil {
				os.Exit(66)
			}
		}
		markReady(cfg)
		for {
			time.Sleep(time.Hour)
		}
	case "write-secret":
		for i := 0; i < max(1, cfg.LogRepeat); i++ {
			fmt.Fprintf(os.Stdout, "stdout secret=%s\n", cfg.Secret)
			fmt.Fprintf(os.Stderr, "stderr secret=%s\n", cfg.Secret)
		}
		fmt.Fprintln(os.Stderr, "open interface take too much time to finish")
		markReady(cfg)
		waitForStop()
	case "escape-immediately":
		if cfg.StartedFile != "" {
			_ = os.WriteFile(cfg.StartedFile, []byte("started"), 0o600)
		}
		if os.Getenv("FAKECONNECT_ESCAPE_CHILD") == "1" {
			if cfg.EscapedFile != "" {
				_ = os.WriteFile(cfg.EscapedFile, []byte("escaped"), 0o600)
			}
			waitForStop()
			return
		}
		child := exec.Command(os.Args[0], "run", "-c", os.Args[3])
		child.Env = append(os.Environ(), "FAKECONNECT_ESCAPE_CHILD=1")
		if err := child.Start(); err != nil {
			os.Exit(66)
		}
		waitForStop()
	case "exit-with-descendant":
		if os.Getenv("FAKECONNECT_LOG_CHILD") == "1" {
			interrupt := make(chan os.Signal, 1)
			signal.Notify(interrupt, os.Interrupt)
			go func() {
				for range interrupt {
				}
			}()
			for {
				time.Sleep(time.Hour)
			}
		}
		child := exec.Command(os.Args[0], "run", "-c", os.Args[3])
		child.Env = append(os.Environ(), "FAKECONNECT_LOG_CHILD=1")
		child.Stdout = os.Stdout
		child.Stderr = os.Stderr
		if err := child.Start(); err != nil {
			os.Exit(66)
		}
		if cfg.ChildPIDFile != "" {
			_ = os.WriteFile(cfg.ChildPIDFile, []byte(strconv.Itoa(child.Process.Pid)), 0o600)
		}
		os.Exit(31)
	case "graceful-with-descendant":
		if os.Getenv("FAKECONNECT_GRACEFUL_CHILD") == "1" {
			interrupt := make(chan os.Signal, 1)
			signal.Notify(interrupt, os.Interrupt)
			go func() {
				for range interrupt {
				}
			}()
			for {
				time.Sleep(time.Hour)
			}
		}
		child := exec.Command(os.Args[0], "run", "-c", os.Args[3])
		child.Env = append(os.Environ(), "FAKECONNECT_GRACEFUL_CHILD=1")
		child.Stdout = os.Stdout
		child.Stderr = os.Stderr
		if err := child.Start(); err != nil {
			os.Exit(66)
		}
		if cfg.ChildPIDFile != "" {
			_ = os.WriteFile(cfg.ChildPIDFile, []byte(strconv.Itoa(child.Process.Pid)), 0o600)
		}
		markReady(cfg)
		waitForStop()
	default:
		os.Exit(64)
	}
}

func markReady(cfg config) {
	if cfg.SuppressReady || cfg.ReadyFile == "" {
		return
	}
	if err := os.WriteFile(cfg.ReadyFile, []byte("ready"), 0o600); err != nil {
		os.Exit(66)
	}
}

func waitForStop() {
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt, syscall.SIGTERM)
	select {
	case <-interrupt:
	case <-time.After(30 * time.Second):
		os.Exit(67)
	}
}
