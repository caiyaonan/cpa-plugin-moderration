//go:build !cshared

// This stub keeps ordinary Go tooling (go vet, go test ./...) working
// without the cshared build tag and a C compiler.
package main

func main() {}
