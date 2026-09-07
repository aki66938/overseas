package contracts

import (
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"corp.example/overseas-access-gateway/internal/localapi"
)

func goTool() string {
	name := "go"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return filepath.Join(runtime.GOROOT(), "bin", name)
}

func targetEnv(goos, arch string) []string {
	var env []string
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if !strings.EqualFold(key, "GOOS") && !strings.EqualFold(key, "GOARCH") && !strings.EqualFold(key, "CGO_ENABLED") {
			env = append(env, entry)
		}
	}
	return append(env, "GOOS="+goos, "GOARCH="+arch, "CGO_ENABLED=0")
}

func TestPortableImportGraph(t *testing.T) {
	for _, target := range []struct{ os, arch string }{{"windows", "amd64"}, {"linux", "amd64"}, {"darwin", "arm64"}} {
		t.Run(target.os, func(t *testing.T) {
			cmd := exec.Command(goTool(), "list", "-deps", "-json", "./internal/localapi", "./internal/lineprobe", "./internal/diagnosticmode")
			cmd.Dir = filepath.Join("..", "..")
			cmd.Env = targetEnv(target.os, target.arch)
			out, err := cmd.Output()
			if err != nil {
				t.Fatal(err)
			}
			decoder := json.NewDecoder(strings.NewReader(string(out)))
			for {
				var pkg struct {
					ImportPath string
					Standard   bool
					Imports    []string
				}
				if err := decoder.Decode(&pkg); err == io.EOF {
					break
				} else if err != nil {
					t.Fatal(err)
				}
				// Standard library OS implementations are expected. Shared project
				// code must not depend on platform adapters or UI libraries.
				if pkg.Standard {
					continue
				}
				// An explicit shared-package allowlist also catches newly named
				// platform bindings and UI frameworks, requiring boundary review.
				switch pkg.ImportPath {
				case "corp.example/overseas-access-gateway/internal/localapi",
					"corp.example/overseas-access-gateway/internal/lineprobe",
					"corp.example/overseas-access-gateway/internal/diagnosticmode",
					"corp.example/overseas-access-gateway/internal/traceevent":
				default:
					t.Errorf("shared graph imports unapproved dependency %s", pkg.ImportPath)
				}
				for _, dependency := range pkg.Imports {
					if dependency == "syscall" || dependency == "C" {
						t.Errorf("%s directly imports native API %s", pkg.ImportPath, dependency)
					}
				}
			}
		})
	}
}

func TestPortableBuild(t *testing.T) {
	for _, target := range []struct{ os, arch string }{{"windows", "amd64"}, {"linux", "amd64"}, {"darwin", "arm64"}} {
		t.Run(target.os, func(t *testing.T) {
			cmd := exec.Command(goTool(), "build", "./...")
			cmd.Dir = filepath.Join("..", "..")
			cmd.Env = targetEnv(target.os, target.arch)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("%s build: %v\n%s", target.os, err, out)
			}
		})
	}
}

func TestLocalAPIProtocolFixture(t *testing.T) {
	data, err := os.ReadFile("local-api-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct{ Request, Response json.RawMessage }
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	request, err := localapi.DecodeRequest(fixture.Request)
	if err != nil {
		t.Fatal(err)
	}
	response, err := localapi.DecodeResponse(fixture.Response, request.ID)
	if err != nil {
		t.Fatal(err)
	}
	if response.Status.Generation != 7 || response.Status.State != "connected" {
		t.Fatalf("lost protocol fields: %+v", response)
	}
}
