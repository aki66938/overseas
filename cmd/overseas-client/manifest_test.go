package main

import (
	"encoding/xml"
	"os"
	"strings"
	"testing"
)

type manifestAssembly struct {
	XMLName    xml.Name             `xml:"assembly"`
	Dependency []manifestDependency `xml:"dependency"`
}

type manifestDependency struct {
	DependentAssembly manifestDependentAssembly `xml:"dependentAssembly"`
}

type manifestDependentAssembly struct {
	Identity manifestIdentity `xml:"assemblyIdentity"`
}

type manifestIdentity struct {
	Name                  string `xml:"name,attr"`
	Type                  string `xml:"type,attr"`
	Version               string `xml:"version,attr"`
	ProcessorArchitecture string `xml:"processorArchitecture,attr"`
	PublicKeyToken        string `xml:"publicKeyToken,attr"`
	Language              string `xml:"language,attr"`
}

func TestAppManifestDeclaresCommonControlsV6Dependency(t *testing.T) {
	contents, err := os.ReadFile("app.manifest")
	if err != nil {
		t.Fatalf("ReadFile(app.manifest): %v", err)
	}
	var assembly manifestAssembly
	if err := xml.Unmarshal(contents, &assembly); err != nil {
		t.Fatalf("Unmarshal manifest: %v", err)
	}

	for _, dependency := range assembly.Dependency {
		identity := dependency.DependentAssembly.Identity
		if identity.Name == "Microsoft.Windows.Common-Controls" {
			if identity.Type != "win32" ||
				identity.Version != "6.0.0.0" ||
				identity.ProcessorArchitecture != "*" ||
				identity.PublicKeyToken != "6595b64144ccf1df" ||
				identity.Language != "*" {
				t.Fatalf("Common Controls dependency = %#v", identity)
			}
			return
		}
	}
	t.Fatal("manifest does not declare Microsoft.Windows.Common-Controls v6")
}

func TestGenerateDirectivePinsManifestCompiler(t *testing.T) {
	contents, err := os.ReadFile("resources_generate.go")
	if err != nil {
		t.Fatalf("ReadFile(resources_generate.go): %v", err)
	}
	want := "//go:generate go run github.com/akavel/rsrc@v0.10.2 -manifest app.manifest -o rsrc_windows_amd64.syso"
	if !strings.Contains(string(contents), want) {
		t.Fatalf("resources_generate.go does not contain %q", want)
	}
}
