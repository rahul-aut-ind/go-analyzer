// Package parser provides AST loading and package inspection utilities for
// go-analyzer. It wraps golang.org/x/tools/go/packages to load a Go module's
// source into memory for subsequent static analysis.
package parser

import (
	"errors"
	"fmt"
	"go/ast"
	"go/token"
	"os"
	"path/filepath"

	"golang.org/x/tools/go/packages"
)

// LoadedPackage bundles all information required by analysis modules for a
// single Go package.
type LoadedPackage struct {
	// Pkg is the fully loaded package descriptor.
	Pkg *packages.Package
	// Files is the list of parsed AST files in this package.
	Files []*ast.File
	// Fset is the shared token.FileSet for position information.
	Fset *token.FileSet
}

// defaultLoadMode is the set of package facts we request from the loader.
const defaultLoadMode = packages.NeedName |
	packages.NeedFiles |
	packages.NeedSyntax |
	packages.NeedTypes |
	packages.NeedTypesInfo |
	packages.NeedImports

// Load loads all Go packages rooted at dir. It returns one LoadedPackage per
// Go package found, sharing a single token.FileSet. An error is returned if
// dir is not a Go module, or if the package loader fails.
func Load(dir string) ([]*LoadedPackage, error) {
	// Validate that dir contains a go.mod so we can give a clear error early.
	if err := requireGoMod(dir); err != nil {
		return nil, err
	}

	fset := token.NewFileSet()

	cfg := &packages.Config{
		Mode:  defaultLoadMode,
		Dir:   dir,
		Fset:  fset,
		Tests: false,
	}

	pkgs, err := packages.Load(cfg, "./...")
	if err != nil {
		return nil, fmt.Errorf("loading packages in %s: %w", dir, err)
	}

	var loaded []*LoadedPackage
	for _, pkg := range pkgs {
		if len(pkg.Errors) > 0 {
			// Log errors but continue — partial results are still useful.
			for _, e := range pkg.Errors {
				_, _ = fmt.Fprintf(os.Stderr, "parser: package %s: %v\n", pkg.PkgPath, e)
			}
		}
		loaded = append(loaded, &LoadedPackage{
			Pkg:   pkg,
			Files: pkg.Syntax,
			Fset:  fset,
		})
	}

	return loaded, nil
}

// requireGoMod returns an error if dir does not contain a go.mod file at any
// level up to the filesystem root. This provides an early, clear diagnostic
// instead of a cryptic packages.Load error.
func requireGoMod(dir string) error {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return fmt.Errorf("resolving path %s: %w", dir, err)
	}

	current := abs
	for {
		candidate := filepath.Join(current, "go.mod")
		if _, err := os.Stat(candidate); err == nil {
			return nil // found
		}

		parent := filepath.Dir(current)
		if parent == current {
			break // reached filesystem root
		}
		current = parent
	}

	return errors.New("go.mod not found: directory is not inside a Go module")
}
