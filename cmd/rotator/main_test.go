package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunVersion(t *testing.T) {
	out, err := os.Create(filepath.Join(t.TempDir(), "out"))
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()

	if code := run([]string{"--version"}, out, os.Stderr); code != 0 {
		t.Fatalf("run --version = %d, want 0", code)
	}
	got, err := os.ReadFile(out.Name())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(got), "kms-intermediate-rotator ") {
		t.Fatalf("version output %q", got)
	}
}
