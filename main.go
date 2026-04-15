// Package main is the entry point for the go-analyzer binary.
// All command wiring lives in the cmd package; this file exists so that
// `go install github.com/rahul-aut-ind/go-analyzer@latest` resolves correctly
// to a package main at the module root.
package main

import "github.com/rahul-aut-ind/go-analyzer/cmd"

func main() { cmd.Execute() }
