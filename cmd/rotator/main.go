// Command rotator is the AWS Lambda that rotates, for AWS Secrets Manager, an
// intermediate CA signed by an AWS KMS key. It runs on the provided.al2023
// custom runtime, as the executable named bootstrap.
//
// This is the skeleton: the rotation itself comes later.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/bpalermo/kms-intermediate-rotator/internal/version"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr *os.File) int {
	fs := flag.NewFlagSet("rotator", flag.ContinueOnError)
	fs.SetOutput(stderr)
	showVersion := fs.Bool("version", false, "print the version and exit")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *showVersion {
		fmt.Fprintf(stdout, "kms-intermediate-rotator %s\n", version.Version)
		return 0
	}
	fmt.Fprintln(stderr, "rotator: the rotation handler is not implemented yet")
	return 1
}
