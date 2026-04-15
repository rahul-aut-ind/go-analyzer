// Package main tests for the sample testdata project.
// These tests exist purely so `go test ./testdata/sample/...` works.
package main

import "testing"

func TestMain_Smoke(t *testing.T) {
	// Verify the package compiles and key functions exist.
	_ = RegexpInsideFunction("123")
	_ = StringConcatInLoop([]string{"a", "b"})
	_ = InsecureTLSConfig()
	_ = WeakHash([]byte("data"))
	_ = InsecureRandom()
	_ = HighComplexityFunction(1, 2, 3, 4, 5, 6)
	_ = DeadCodeAfterReturn()
	RaceLoopCapture()
	RaceMapWrite()
}
