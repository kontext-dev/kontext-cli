package main

import (
	"fmt"
	"os"

	"github.com/kontext-security/kontext-cli/internal/vomcbench"
)

func main() {
	if err := vomcbench.Run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
