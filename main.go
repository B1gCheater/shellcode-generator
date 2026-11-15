package main

import (
	"os"

	"github.com/B1gCheater/shellcode-generator/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}
