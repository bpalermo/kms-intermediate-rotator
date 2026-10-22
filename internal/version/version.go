// Package version exposes the build version of the rotator.
package version

// Version is the build version: `git describe --tags --always --dirty` of
// the commit the binary was built from, or the release tag, stamped at link
// time from bazel/workspace_status.sh (see x_defs in this package's BUILD
// file). It is "dev" in a build without stamping, such as a test.
var Version = "dev"
