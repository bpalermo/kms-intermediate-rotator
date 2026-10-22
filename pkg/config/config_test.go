package config_test

import (
	"context"
	"crypto/elliptic"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/ssm/types"

	"github.com/bpalermo/kms-intermediate-rotator/internal/testca"
	"github.com/bpalermo/kms-intermediate-rotator/pkg/config"
	"github.com/bpalermo/kms-intermediate-rotator/pkg/intermediate"
)

const secretARN = "arn:aws:secretsmanager:us-east-1:111122223333:secret:example-AbCdEf"

func rootPEM(t *testing.T) string {
	t.Helper()
	return testca.NewRoot(t, testca.NewKey(t, elliptic.P384()), time.Hour).PEM()
}

// document returns a valid configuration with change applied, as JSON.
func document(t *testing.T, root string, change func(cfg, secret map[string]any)) string {
	t.Helper()
	secret := map[string]any{
		"subject":  map[string]any{"common_name": "Example Intermediate CA", "organization": []string{"Example"}, "country": []string{"US"}},
		"key_type": "ec-p384",
		"validity": "720h",
		"name_constraints": map[string]any{
			"permitted_uri_domains": []string{"example.org"},
			"permitted_dns_domains": []string{".example.org"},
		},
	}
	cfg := map[string]any{
		"kms_key_id":       "alias/example-root",
		"root_certificate": root,
		"secrets":          map[string]any{secretARN: secret},
	}
	if change != nil {
		change(cfg, secret)
	}
	b, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

type fakeSSM struct {
	values map[string]string
	calls  int
}

func (f *fakeSSM) GetParameter(_ context.Context, in *ssm.GetParameterInput, _ ...func(*ssm.Options)) (*ssm.GetParameterOutput, error) {
	f.calls++
	if !aws.ToBool(in.WithDecryption) {
		return nil, errors.New("fakeSSM: WithDecryption must be set for SecureString")
	}
	v, ok := f.values[aws.ToString(in.Name)]
	if !ok {
		return nil, &types.ParameterNotFound{}
	}
	return &ssm.GetParameterOutput{Parameter: &types.Parameter{Name: in.Name, Value: aws.String(v)}}, nil
}

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestLoad(t *testing.T) {
	doc := document(t, rootPEM(t), nil)
	params := &fakeSSM{values: map[string]string{"/example/rotator": doc}}
	for _, tc := range []struct {
		name      string
		env       map[string]string
		wantErr   string
		wantCalls int
	}{
		{"inline", map[string]string{config.EnvConfig: doc}, "", 0},
		{"parameter", map[string]string{config.EnvConfigParameter: "/example/rotator"}, "", 1},
		{"both", map[string]string{config.EnvConfig: doc, config.EnvConfigParameter: "/example/rotator"}, "exactly one", 0},
		{"neither", map[string]string{}, "exactly one", 0},
		{"missing parameter", map[string]string{config.EnvConfigParameter: "/example/missing"}, "read SSM parameter", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			params.calls = 0
			cfg, err := config.Load(context.Background(), env(tc.env), params)
			if params.calls != tc.wantCalls {
				t.Errorf("SSM calls %d, want %d", params.calls, tc.wantCalls)
			}
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("Load = %v, want an error with %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if cfg.KMSKeyID != "alias/example-root" || cfg.Root == nil || len(cfg.Secrets) != 1 {
				t.Fatalf("config %+v", cfg)
			}
		})
	}
}

func TestParseDefaults(t *testing.T) {
	doc := document(t, rootPEM(t), func(_, s map[string]any) {
		delete(s, "key_type")
		delete(s, "validity")
		delete(s, "name_constraints")
	})
	cfg, err := config.Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	p := cfg.Secrets[secretARN].Profile()
	if p.KeyType != intermediate.KeyTypeECP256 || p.Validity != 2160*time.Hour || p.MaxPathLen != 1 || !p.NameConstraints.Empty() {
		t.Fatalf("defaults %+v", p)
	}
}

func TestParseProfile(t *testing.T) {
	doc := document(t, rootPEM(t), func(_, s map[string]any) { s["max_path_len"] = 0 })
	cfg, err := config.Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	p := cfg.Secrets[secretARN].Profile()
	if p.MaxPathLen != 0 || p.KeyType != intermediate.KeyTypeECP384 || p.Validity != 720*time.Hour {
		t.Fatalf("profile %+v", p)
	}
	if p.Subject.CommonName != "Example Intermediate CA" || p.Subject.Country[0] != "US" {
		t.Fatalf("subject %+v", p.Subject)
	}
	if p.NameConstraints.PermittedURIDomains[0] != "example.org" || p.NameConstraints.PermittedDNSDomains[0] != ".example.org" {
		t.Fatalf("name constraints %+v", p.NameConstraints)
	}
}

func TestParseRejects(t *testing.T) {
	root := rootPEM(t)
	for _, tc := range []struct {
		name    string
		change  func(cfg, secret map[string]any)
		wantErr string
	}{
		{"invalid duration", func(_, s map[string]any) { s["validity"] = "90 days" }, "duration"},
		{"zero duration", func(_, s map[string]any) { s["validity"] = "0s" }, "not positive"},
		{"negative duration", func(_, s map[string]any) { s["validity"] = "-1h" }, "not positive"},
		{"numeric duration", func(_, s map[string]any) { s["validity"] = 3600 }, "duration"},
		{"unknown key type", func(_, s map[string]any) { s["key_type"] = "ed25519" }, "unknown key_type"},
		{"negative path length", func(_, s map[string]any) { s["max_path_len"] = -1 }, "max_path_len"},
		{"no common name", func(_, s map[string]any) { s["subject"] = map[string]any{} }, "common_name"},
		{"unknown field", func(_, s map[string]any) { s["validty"] = "1h" }, "unknown field"},
		{"bad domain", func(_, s map[string]any) {
			s["name_constraints"] = map[string]any{"permitted_uri_domains": []string{"spiffe://example.org"}}
		}, "not a domain"},
		{"no kms key", func(c, _ map[string]any) { delete(c, "kms_key_id") }, "kms_key_id"},
		{"no root", func(c, _ map[string]any) { delete(c, "root_certificate") }, "root_certificate"},
		{"two roots", func(c, _ map[string]any) { c["root_certificate"] = root + root }, "exactly one"},
		{"no secrets", func(c, _ map[string]any) { c["secrets"] = map[string]any{} }, "at least one"},
		{"not an ARN", func(c, s map[string]any) { c["secrets"] = map[string]any{"example": s} }, "not a Secrets Manager secret ARN"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := config.Parse([]byte(document(t, root, tc.change)))
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Parse = %v, want an error with %q", err, tc.wantErr)
			}
		})
	}
}

func TestLookup(t *testing.T) {
	partial := strings.TrimSuffix(secretARN, "-AbCdEf")
	for _, tc := range []struct {
		name       string
		configured string
		arn        string
		want       bool
	}{
		{"full ARN", secretARN, secretARN, true},
		{"partial ARN configured", partial, secretARN, true},
		{"other secret", secretARN, "arn:aws:secretsmanager:us-east-1:111122223333:secret:other-AbCdEf", false},
		{"other account", secretARN, "arn:aws:secretsmanager:us-east-1:444455556666:secret:example-AbCdEf", false},
		{"full ARN configured, partial asked", secretARN, partial, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc := document(t, rootPEM(t), func(c, s map[string]any) { c["secrets"] = map[string]any{tc.configured: s} })
			cfg, err := config.Parse([]byte(doc))
			if err != nil {
				t.Fatal(err)
			}
			if _, _, ok := cfg.Lookup(tc.arn); ok != tc.want {
				t.Fatalf("Lookup(%s) = %t, want %t", tc.arn, ok, tc.want)
			}
		})
	}
}
