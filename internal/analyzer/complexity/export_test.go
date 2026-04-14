// Package complexity exposes internal functions for white-box testing via the
// standard Go export_test.go pattern. This file is compiled only during
// testing because its name ends in _test.go.
package complexity

import (
	"go/ast"
)

// ExportedCyclomaticComplexity is the exported alias used in complexity_test
// to exercise the unexported cyclomaticComplexity function.
var ExportedCyclomaticComplexity = cyclomaticComplexity

// ExportedMaxNestingDepth is the exported alias used in complexity_test
// to exercise the unexported maxNestingDepth function.
var ExportedMaxNestingDepth = func(body *ast.BlockStmt) int {
	return maxNestingDepth(body)
}

// ExportedCountParams is the exported alias used in complexity_test to
// exercise the unexported countParams function.
var ExportedCountParams = countParams
