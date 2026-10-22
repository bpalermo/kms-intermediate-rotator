package main

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/bpalermo/kms-intermediate-rotator/pkg/rotation"
)

func noStart(t *testing.T) func(func(context.Context, rotation.Event) error) {
	return func(func(context.Context, rotation.Event) error) {
		t.Fatal("the Lambda must not start")
	}
}

func TestRunVersion(t *testing.T) {
	var out bytes.Buffer
	if code := run([]string{"--version"}, &out, &out, func(string) string { return "" }, noStart(t)); code != 0 {
		t.Fatalf("run --version = %d, want 0", code)
	}
	if !strings.HasPrefix(out.String(), "kms-intermediate-rotator ") {
		t.Fatalf("version output %q", out.String())
	}
}

// Without exactly one configuration source the rotator refuses to start,
// before any AWS call, and says why in one JSON log line.
func TestRunRefusesWithoutConfig(t *testing.T) {
	for name, env := range map[string]map[string]string{
		"neither": {},
		"both": {
			"ROTATOR_CONFIG":           "{}",
			"ROTATOR_CONFIG_PARAMETER": "/example/rotator",
		},
	} {
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			getenv := func(k string) string { return env[k] }
			if code := run(nil, &out, &out, getenv, noStart(t)); code != 1 {
				t.Fatalf("run = %d, want 1", code)
			}
			var line map[string]any
			if err := json.Unmarshal(out.Bytes(), &line); err != nil {
				t.Fatalf("log is not one JSON line: %q: %v", out.String(), err)
			}
			if msg, _ := line["error"].(string); line["level"] != "ERROR" || !strings.Contains(msg, "exactly one") {
				t.Fatalf("log line %v", line)
			}
		})
	}
}

func TestRunRejectsUnknownFlag(t *testing.T) {
	var out bytes.Buffer
	if code := run([]string{"--nope"}, &out, &out, func(string) string { return "" }, noStart(t)); code != 2 {
		t.Fatalf("run = %d, want 2", code)
	}
}
