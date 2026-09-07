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

func targetEnv(goos, arch, cgo string) []string {
	var env []string
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if !strings.EqualFold(key, "GOOS") && !strings.EqualFold(key, "GOARCH") && !strings.EqualFold(key, "CGO_ENABLED") {
			env = append(env, entry)
		}
	}
	return append(env, "GOOS="+goos, "GOARCH="+arch, "CGO_ENABLED="+cgo)
}

// importGraphViolations inspects source metadata only; it never compiles C.
func importGraphViolations(t *testing.T, dir, goos, arch, cgo string, roots ...string) []string {
	t.Helper()
	args := append([]string{"list", "-deps", "-json"}, roots...)
	cmd := exec.Command(goTool(), args...)
	cmd.Dir = dir
	cmd.Env = targetEnv(goos, arch, cgo)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("list %s/cgo%s: %v", goos, cgo, err)
	}
	decoder := json.NewDecoder(strings.NewReader(string(out)))
	var violations []string
	for {
		var pkg struct {
			ImportPath string
			Standard   bool
			Imports    []string
			CgoFiles   []string
		}
		if err := decoder.Decode(&pkg); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		if pkg.Standard {
			continue
		}
		if len(pkg.CgoFiles) != 0 {
			violations = append(violations, pkg.ImportPath+" contains cgo sources: "+strings.Join(pkg.CgoFiles, ", "))
		}
		switch pkg.ImportPath {
		case "corp.example/overseas-access-gateway/internal/localapi",
			"corp.example/overseas-access-gateway/internal/lineprobe",
			"corp.example/overseas-access-gateway/internal/diagnosticmode",
			"corp.example/overseas-access-gateway/internal/traceevent":
		default:
			violations = append(violations, "shared graph imports unapproved dependency "+pkg.ImportPath)
		}
		for _, dependency := range pkg.Imports {
			if dependency == "syscall" || dependency == "C" {
				violations = append(violations, pkg.ImportPath+" directly imports native API "+dependency)
			}
		}
	}
	return violations
}

func TestPortableImportGraph(t *testing.T) {
	for _, target := range []struct{ os, arch string }{{"windows", "amd64"}, {"linux", "amd64"}, {"darwin", "arm64"}} {
		for _, cgo := range []string{"0", "1"} {
			t.Run(target.os+"/cgo"+cgo, func(t *testing.T) {
				for _, violation := range importGraphViolations(t, filepath.Join("..", ".."), target.os, target.arch, cgo, "./internal/localapi", "./internal/lineprobe", "./internal/diagnosticmode") {
					t.Error(violation)
				}
			})
		}
	}
}

func TestPortableBuild(t *testing.T) {
	for _, target := range []struct{ os, arch string }{{"windows", "amd64"}, {"linux", "amd64"}, {"darwin", "arm64"}} {
		t.Run(target.os, func(t *testing.T) {
			cmd := exec.Command(goTool(), "build", "./...")
			cmd.Dir = filepath.Join("..", "..")
			cmd.Env = targetEnv(target.os, target.arch, "0")
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
