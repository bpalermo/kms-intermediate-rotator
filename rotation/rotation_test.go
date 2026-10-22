package rotation_test

import (
	"bytes"
	"context"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/json"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	intermediateca "github.com/bpalermo/intermediate-ca-format"

	"github.com/bpalermo/kms-intermediate-rotator/config"
	"github.com/bpalermo/kms-intermediate-rotator/intermediate"
	"github.com/bpalermo/kms-intermediate-rotator/internal/kmsfake"
	"github.com/bpalermo/kms-intermediate-rotator/internal/testca"
	"github.com/bpalermo/kms-intermediate-rotator/kmssigner"
	"github.com/bpalermo/kms-intermediate-rotator/rotation"
)

const (
	keyID      = "alias/example-root"
	secretName = "example"
	secretARN  = "arn:aws:secretsmanager:us-east-1:111122223333:secret:example-AbCdEf"
	token      = "11111111-2222-3333-4444-555555555555"
	oldVersion = "00000000-0000-0000-0000-000000000000"
)

type env struct {
	root    *testca.Root
	kms     *kmsfake.KMS
	sm      *fakeSM
	cfg     *config.Config
	rotator *rotation.Rotator
	logs    *bytes.Buffer
	// clock is the rotator's time; tests move it forward.
	clock time.Time
}

func newEnv(t *testing.T) *env {
	t.Helper()
	root := testca.NewRoot(t, testca.NewKey(t, elliptic.P384()), 10*365*24*time.Hour)
	doc, err := json.Marshal(map[string]any{
		"kms_key_id":       keyID,
		"root_certificate": root.PEM(),
		"secrets": map[string]any{secretARN: map[string]any{
			"subject":      map[string]any{"common_name": "Example Intermediate CA", "organization": []string{"Example"}},
			"validity":     "2160h",
			"max_path_len": 0,
			"name_constraints": map[string]any{
				"permitted_uri_domains": []string{"example.org"},
				"permitted_dns_domains": []string{".example.org"},
			},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse(doc)
	if err != nil {
		t.Fatal(err)
	}
	fake := kmsfake.New(keyID, root.Key)
	signer, err := kmssigner.New(context.Background(), fake, keyID, cfg.SigningAlgorithm, cfg.Root.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	sm := newFakeSM(secretARN, secretName)
	sm.version(oldVersion, aws.String("{}"), "AWSCURRENT")
	sm.version(token, nil, "AWSPENDING")
	logs := &bytes.Buffer{}
	e := &env{
		root: root, kms: fake, sm: sm, cfg: cfg, logs: logs, clock: time.Now(),
		rotator: &rotation.Rotator{
			SecretsManager: sm,
			Config:         cfg,
			Signer:         signer,
			Logger:         slog.New(slog.NewJSONHandler(logs, nil)),
		},
	}
	e.rotator.Now = func() time.Time { return e.clock }
	return e
}

func (e *env) step(step string) error {
	return e.rotator.Handle(context.Background(), rotation.Event{SecretID: secretARN, ClientRequestToken: token, Step: step})
}

func TestFullRotation(t *testing.T) {
	e := newEnv(t)
	for _, step := range []string{rotation.StepCreate, rotation.StepSet, rotation.StepTest, rotation.StepFinish} {
		if err := e.step(step); err != nil {
			t.Fatalf("%s: %v", step, err)
		}
	}
	if got := e.sm.labels(token); !slices.Contains(got, "AWSCURRENT") {
		t.Fatalf("token labels %v, want AWSCURRENT", got)
	}
	if got := e.sm.labels(oldVersion); !slices.Equal(got, []string{"AWSPREVIOUS"}) {
		t.Fatalf("old version labels %v, want [AWSPREVIOUS]", got)
	}
	if len(e.sm.updates) != 1 || aws.ToString(e.sm.updates[0].RemoveFromVersionId) != oldVersion || aws.ToString(e.sm.updates[0].MoveToVersionId) != token {
		t.Fatalf("updates %+v", e.sm.updates)
	}
	// A reader of the shared format accepts what was stored.
	b, err := intermediateca.Decode([]byte(e.sm.value(token)))
	if err != nil {
		t.Fatal(err)
	}
	if !b.Root.Equal(e.root.Cert) || b.Cert.Subject.CommonName != "Example Intermediate CA" || !b.Cert.MaxPathLenZero {
		t.Fatalf("issued %s pathlen0=%t", b.Cert.Subject, b.Cert.MaxPathLenZero)
	}
	if e.kms.Signs() != 1 {
		t.Fatalf("KMS Sign calls %d, want 1", e.kms.Signs())
	}

	// The issued certificate is logged once, without key material.
	logs := e.logs.String()
	if strings.Contains(logs, "PRIVATE KEY") || strings.Contains(logs, "BEGIN") {
		t.Fatal("key or certificate material in the logs")
	}
	var issued map[string]any
	for line := range strings.Lines(logs) {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("log line is not JSON: %q", line)
		}
		if m["msg"] == "issued intermediate certificate" {
			issued = m
		}
	}
	want := map[string]any{
		"secret_arn":        secretARN,
		"serial":            b.Cert.SerialNumber.Text(16),
		"not_after":         b.Cert.NotAfter.UTC().Format(time.RFC3339),
		"public_key_sha256": rotation.PublicKeySHA256(b.Cert),
	}
	for k, v := range want {
		if issued[k] != v {
			t.Errorf("log %s = %v, want %v", k, issued[k], v)
		}
	}
}

func TestCreateSecretIdempotent(t *testing.T) {
	e := newEnv(t)
	if err := e.step(rotation.StepCreate); err != nil {
		t.Fatal(err)
	}
	first := e.sm.value(token)
	if err := e.step(rotation.StepCreate); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if e.kms.Signs() != 1 || e.sm.puts != 1 {
		t.Fatalf("after a retry: %d signs, %d puts; want 1 and 1", e.kms.Signs(), e.sm.puts)
	}
	if e.sm.value(token) != first {
		t.Fatal("the pending value changed on retry")
	}
}

func TestPreconditions(t *testing.T) {
	for _, tc := range []struct {
		name    string
		setup   func(*env)
		event   rotation.Event
		wantErr string // empty: success with nothing done
	}{
		{
			name: "token already AWSCURRENT",
			setup: func(e *env) {
				e.sm.version(oldVersion, aws.String("{}"))
				e.sm.version(token, aws.String("{}"), "AWSCURRENT")
			},
			event: rotation.Event{SecretID: secretARN, ClientRequestToken: token, Step: rotation.StepCreate},
		},
		{
			name:    "token not AWSPENDING",
			setup:   func(e *env) { e.sm.version(token, nil, "AWSPREVIOUS") },
			event:   rotation.Event{SecretID: secretARN, ClientRequestToken: token, Step: rotation.StepCreate},
			wantErr: "not AWSPENDING",
		},
		{
			name:    "token not a version",
			event:   rotation.Event{SecretID: secretARN, ClientRequestToken: "99999999-0000-0000-0000-000000000000", Step: rotation.StepCreate},
			wantErr: "has no version",
		},
		{
			name:    "rotation disabled",
			setup:   func(e *env) { e.sm.rotation = false },
			event:   rotation.Event{SecretID: secretARN, ClientRequestToken: token, Step: rotation.StepCreate},
			wantErr: "rotation enabled",
		},
		{
			name:    "unknown secret ARN",
			event:   rotation.Event{SecretID: "arn:aws:secretsmanager:us-east-1:111122223333:secret:other-AbCdEf", ClientRequestToken: token, Step: rotation.StepCreate},
			wantErr: "not configured",
		},
		{
			name:    "unknown step",
			event:   rotation.Event{SecretID: secretARN, ClientRequestToken: token, Step: "deleteSecret"},
			wantErr: "unknown step",
		},
		{
			name:    "no token",
			event:   rotation.Event{SecretID: secretARN, Step: rotation.StepCreate},
			wantErr: "ClientRequestToken",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			if tc.setup != nil {
				tc.setup(e)
			}
			err := e.rotator.Handle(context.Background(), tc.event)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Handle = %v, want an error with %q", err, tc.wantErr)
			}
			if e.kms.Signs() != 0 || e.sm.puts != 0 || len(e.sm.updates) != 0 {
				t.Fatalf("something was done: %d signs, %d puts, %d updates", e.kms.Signs(), e.sm.puts, len(e.sm.updates))
			}
		})
	}
}

// A SecretId given as the secret's name resolves to its ARN, and the
// RotationToken field is accepted.
func TestSecretIDByName(t *testing.T) {
	e := newEnv(t)
	var ev rotation.Event
	raw := `{"SecretId":"example","ClientRequestToken":"` + token + `","Step":"createSecret","RotationToken":"opaque"}`
	if err := json.Unmarshal([]byte(raw), &ev); err != nil {
		t.Fatal(err)
	}
	if err := e.rotator.Handle(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	if e.sm.puts != 1 {
		t.Fatalf("puts %d, want 1", e.sm.puts)
	}
}

func TestTestSecretRejects(t *testing.T) {
	for _, tc := range []struct {
		name    string
		pending func(t *testing.T, e *env) string
		wantErr string
		// wantIs is the intermediateca sentinel of a value a reader of the
		// format refuses; nil for this rotator's own checks.
		wantIs error
	}{
		{"wrong key", func(t *testing.T, e *env) string {
			b := issue(t, e.root, profileOf(e))
			b.Key, _ = intermediate.GenerateKey(intermediate.KeyTypeECP256)
			return encode(t, b)
		}, "does not match", intermediateca.ErrKeyMismatch},
		{"wrong root", func(t *testing.T, e *env) string {
			other := testca.NewRoot(t, testca.NewKey(t, elliptic.P384()), 365*24*time.Hour)
			return encode(t, issue(t, other, profileOf(e)))
		}, "not the configured root", nil},
		{"missing constraints", func(t *testing.T, e *env) string {
			p := profileOf(e)
			p.NameConstraints = intermediate.NameConstraints{}
			return encode(t, issue(t, e.root, p))
		}, "name constraints", nil},
		{"short validity", func(t *testing.T, e *env) string {
			p := profileOf(e)
			p.Validity = 10 * 24 * time.Hour
			return encode(t, issue(t, e.root, p))
		}, "issued at", nil},
		{"other path length", func(t *testing.T, e *env) string {
			p := profileOf(e)
			p.MaxPathLen = 1
			return encode(t, issue(t, e.root, p))
		}, "path length", nil},
		{"unknown format", func(t *testing.T, e *env) string {
			return strings.Replace(encode(t, issue(t, e.root, profileOf(e))), "intermediate-ca/v1", "intermediate-ca/v0", 1)
		}, "invalid secret", intermediateca.ErrInvalid},
		{"not the format", func(*testing.T, *env) string { return `{"cert":"x"}` }, "invalid secret", intermediateca.ErrInvalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			e.sm.version(token, aws.String(tc.pending(t, e)), "AWSPENDING")
			err := e.step(rotation.StepTest)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("testSecret = %v, want an error with %q", err, tc.wantErr)
			}
			if tc.wantIs != nil && !errors.Is(err, tc.wantIs) {
				t.Fatalf("testSecret = %v, want %v", err, tc.wantIs)
			}
			// Every rejection of a stored value says how to get unstuck.
			if !strings.Contains(err.Error(), "--remove-from-version-id "+token) {
				t.Fatalf("testSecret = %v, want the recovery command", err)
			}
		})
	}
}

func profileOf(e *env) intermediate.Profile {
	_, s, _ := e.cfg.Lookup(secretARN)
	return s.Profile
}

func issue(t *testing.T, root *testca.Root, p intermediate.Profile) *intermediateca.Bundle {
	t.Helper()
	key, err := intermediate.GenerateKey(p.KeyType)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := intermediate.Issue(p, key.Public(), root.Cert, root.Key, x509.UnknownSignatureAlgorithm, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return &intermediateca.Bundle{Cert: cert, Key: key, Root: root.Cert}
}

func encode(t *testing.T, b *intermediateca.Bundle) string {
	t.Helper()
	s, err := intermediateca.Encode(b)
	if err != nil {
		t.Fatal(err)
	}
	return string(s)
}

func TestFinishSecret(t *testing.T) {
	e := newEnv(t)
	// A third version that is AWSPREVIOUS from an earlier rotation.
	e.sm.version("aaaaaaaa-0000-0000-0000-000000000000", aws.String("{}"), "AWSPREVIOUS")
	if err := e.step(rotation.StepCreate); err != nil {
		t.Fatal(err)
	}
	if err := e.step(rotation.StepFinish); err != nil {
		t.Fatal(err)
	}
	if got := e.sm.labels(token); !slices.Contains(got, "AWSCURRENT") {
		t.Fatalf("token labels %v", got)
	}
	if got := e.sm.labels(oldVersion); !slices.Equal(got, []string{"AWSPREVIOUS"}) {
		t.Fatalf("old current labels %v, want [AWSPREVIOUS]", got)
	}
	if got := e.sm.labels("aaaaaaaa-0000-0000-0000-000000000000"); len(got) != 0 {
		t.Fatalf("older version labels %v, want none", got)
	}
	// Once AWSCURRENT, finishing again is a success that changes nothing.
	if err := e.step(rotation.StepFinish); err != nil {
		t.Fatal(err)
	}
	if len(e.sm.updates) != 1 {
		t.Fatalf("updates %d, want 1", len(e.sm.updates))
	}
}

// A rotation that failed after createSecret is retried, later, with the
// same AWSPENDING version: it passes testSecret while enough of it is left,
// and fails with the way out once too little is.
func TestRetryLater(t *testing.T) {
	day := 24 * time.Hour
	for _, tc := range []struct {
		name  string
		after time.Duration
		ok    bool
	}{
		{"a day later", day, true},
		{"a week later", 7 * day, true},
		{"most of the validity later", 80 * day, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			if err := e.step(rotation.StepCreate); err != nil {
				t.Fatal(err)
			}
			e.clock = e.clock.Add(tc.after)
			// The retry: createSecret reuses the value, then testSecret.
			if err := e.step(rotation.StepCreate); err != nil {
				t.Fatal(err)
			}
			err := e.step(rotation.StepTest)
			if tc.ok {
				if err != nil {
					t.Fatalf("testSecret: %v", err)
				}
				if err := e.step(rotation.StepFinish); err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), "too little validity left") ||
				!strings.Contains(err.Error(), "update-secret-version-stage") {
				t.Fatalf("testSecret = %v, want too little validity left and the recovery command", err)
			}
			if e.kms.Signs() != 1 {
				t.Fatalf("KMS Sign calls %d, want 1", e.kms.Signs())
			}
		})
	}
}

// A path length the root has no room for is caught before it is stored,
// and in a stored pending version. Config validation normally prevents it;
// the configuration is changed behind its back here.
func TestPathLengthBeyondRoot(t *testing.T) {
	e := newEnv(t)
	tooLong := 2 // the root's path length is 2: at most 1 under it
	_, sc, _ := e.cfg.Lookup(secretARN)
	sc.Profile.MaxPathLen = tooLong
	err := e.step(rotation.StepCreate)
	if err == nil || !strings.Contains(err.Error(), "path length") {
		t.Fatalf("createSecret = %v, want a path length error", err)
	}
	if e.sm.puts != 0 {
		t.Fatal("an intermediate with a path length too long was stored")
	}
	e.sm.version(token, aws.String(encode(t, issue(t, e.root, profileOf(e)))), "AWSPENDING")
	if err := e.step(rotation.StepTest); err == nil || !strings.Contains(err.Error(), "path length") {
		t.Fatalf("testSecret = %v, want a path length error", err)
	}
}

// Two invocations for the same token: the one that loses the
// PutSecretValue race finds the winner's version and succeeds.
func TestCreateSecretConcurrent(t *testing.T) {
	e := newEnv(t)
	winner := encode(t, issue(t, e.root, profileOf(e)))
	e.sm.beforePut = func() {
		e.sm.mu.Lock()
		defer e.sm.mu.Unlock()
		e.sm.values[token] = aws.String(winner)
	}
	if err := e.step(rotation.StepCreate); err != nil {
		t.Fatal(err)
	}
	if e.sm.value(token) != winner {
		t.Fatal("the winner's value was replaced")
	}
	if strings.Contains(e.logs.String(), "issued intermediate certificate") {
		t.Fatal("the losing certificate was logged as issued")
	}
}

func TestCreateSecretRotationToken(t *testing.T) {
	for _, rt := range []string{"", "opaque-rotation-token"} {
		e := newEnv(t)
		ev := rotation.Event{SecretID: secretARN, ClientRequestToken: token, Step: rotation.StepCreate, RotationToken: rt}
		if err := e.rotator.Handle(context.Background(), ev); err != nil {
			t.Fatal(err)
		}
		got := e.sm.lastPut.RotationToken
		if (rt == "" && got != nil) || (rt != "" && aws.ToString(got) != rt) {
			t.Fatalf("RotationToken %v, want %q", got, rt)
		}
		if rt != "" && strings.Contains(e.logs.String(), rt) {
			t.Fatal("the rotation token was logged")
		}
	}
}

// Rotation configured without rotating immediately: Secrets Manager runs
// testSecret alone, with no value to test. That succeeds; a value is always
// tested.
func TestConfigurationTest(t *testing.T) {
	for _, tc := range []struct {
		name  string
		token string
	}{
		{"pending version without a value", token},
		{"token not a version", "99999999-0000-0000-0000-000000000000"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			ev := rotation.Event{SecretID: secretARN, ClientRequestToken: tc.token, Step: rotation.StepTest}
			if err := e.rotator.Handle(context.Background(), ev); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(e.logs.String(), "configuration test") {
				t.Fatal("not logged as a configuration test")
			}
			if e.kms.Signs() != 0 || e.sm.puts != 0 || len(e.sm.updates) != 0 {
				t.Fatal("a configuration test changed something")
			}
		})
	}
	e := newEnv(t)
	e.sm.version(token, aws.String("{}"), "AWSPENDING")
	if err := e.step(rotation.StepTest); err == nil {
		t.Fatal("a pending version with a value was not tested")
	}
}
