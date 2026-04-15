package parser

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad_SampleProject(t *testing.T) {
	// Resolve path to testdata/sample relative to the repo root.
	// parser_test.go lives in internal/parser/, so go up two levels.
	dir := filepath.Join("..", "..", "testdata", "sample")

	if _, err := os.Stat(filepath.Join(dir, "go.mod")); os.IsNotExist(err) {
		t.Skip("testdata/sample not available yet — skipping parser integration test")
	}

	pkgs, err := Load(dir)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if len(pkgs) == 0 {
		t.Fatal("Load() returned zero packages")
	}

	for _, lp := range pkgs {
		if lp.Fset == nil {
			t.Errorf("package %s: Fset is nil", lp.Pkg.PkgPath)
		}
		if lp.Pkg == nil {
			t.Error("LoadedPackage.Pkg is nil")
		}
	}
}

func TestLoad_NoGoMod(t *testing.T) {
	dir := t.TempDir()

	_, err := Load(dir)
	if err == nil {
		t.Fatal("Load() should fail for a directory without go.mod")
	}
}

func TestRequireGoMod(t *testing.T) {
	// Directory that IS a Go module (repo root has go.mod).
	repoRoot := filepath.Join("..", "..")
	if err := requireGoMod(repoRoot); err != nil {
		t.Errorf("requireGoMod(repo root) unexpected error: %v", err)
	}

	// Temp directory with no go.mod.
	tmp := t.TempDir()
	if err := requireGoMod(tmp); err == nil {
		t.Error("requireGoMod(no go.mod) should return error")
	}
}

func TestLoad_WithGoMod(t *testing.T) {
	// Create a minimal Go module in a temp directory and try to load it.
	dir := t.TempDir()

	goMod := `module example.com/test

go 1.22
`
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(goMod), 0o644); err != nil {
		t.Fatal(err)
	}

	mainGo := `package main

import "fmt"

func main() {
	fmt.Println("hello")
}
`
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(mainGo), 0o644); err != nil {
		t.Fatal(err)
	}

	pkgs, err := Load(dir)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if len(pkgs) == 0 {
		t.Fatal("Load() returned zero packages for minimal module")
	}
	if pkgs[0].Fset == nil {
		t.Error("Fset is nil")
	}
}
