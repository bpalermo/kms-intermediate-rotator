package config_test

import (
	"context"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/ssm/types"

	"github.com/bpalermo/kms-intermediate-rotator/config"
	"github.com/bpalermo/kms-intermediate-rotator/intermediate"
	"github.com/bpalermo/kms-intermediate-rotator/internal/testca"
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
	p := cfg.Secrets[secretARN].Profile
	if p.KeyType != intermediate.KeyTypeECP256 || p.Validity != 2160*time.Hour || p.MaxPathLen != 1 || !p.NameConstraints.Empty() ||
		p.MinRemaining != 1080*time.Hour {
		t.Fatalf("defaults %+v", p)
	}
	if cfg.SigningAlgorithm != "" {
		t.Fatalf("signing algorithm %q, want none", cfg.SigningAlgorithm)
	}
}

func TestParseProfile(t *testing.T) {
	doc := document(t, rootPEM(t), func(c, s map[string]any) {
		c["signing_algorithm"] = "ECDSA_SHA_384"
		s["max_path_len"] = 0
		s["min_remaining"] = "100h"
		s["subject"] = map[string]any{
			"common_name": "Example Intermediate CA", "organization": []string{"Example"}, "organizational_unit": []string{"PKI"},
			"country": []string{"US"}, "province": []string{"Example State"}, "locality": []string{"Example City"},
		}
	})
	cfg, err := config.Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SigningAlgorithm != "ECDSA_SHA_384" {
		t.Fatalf("signing algorithm %q", cfg.SigningAlgorithm)
	}
	p := cfg.Secrets[secretARN].Profile
	if p.MaxPathLen != 0 || p.KeyType != intermediate.KeyTypeECP384 || p.Validity != 720*time.Hour || p.MinRemaining != 100*time.Hour {
		t.Fatalf("profile %+v", p)
	}
	sub := p.Subject
	if sub.CommonName != "Example Intermediate CA" || sub.Organization[0] != "Example" || sub.OrganizationalUnit[0] != "PKI" ||
		sub.Country[0] != "US" || sub.Province[0] != "Example State" || sub.Locality[0] != "Example City" {
		t.Fatalf("subject %+v", sub)
	}
	if p.NameConstraints.PermittedURIDomains[0] != "example.org" || p.NameConstraints.PermittedDNSDomains[0] != ".example.org" {
		t.Fatalf("name constraints %+v", p.NameConstraints)
	}
}

// The configurations that were valid before the schema still are: the forms
// of each value the schema accepts.
func TestParseAccepts(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(cfg, secret map[string]any)
	}{
		{"key ID", func(c, _ map[string]any) { c["kms_key_id"] = "00000000-0000-0000-0000-000000000000" }},
		{"multi-Region key ID", func(c, _ map[string]any) { c["kms_key_id"] = "mrk-00000000000000000000000000000000" }},
		{"key ARN", func(c, _ map[string]any) {
			c["kms_key_id"] = "arn:aws:kms:us-east-1:111122223333:key/00000000-0000-0000-0000-000000000000"
		}},
		{"alias ARN", func(c, _ map[string]any) { c["kms_key_id"] = "arn:aws:kms:us-east-1:111122223333:alias/example-root" }},
		{"other partition", func(c, s map[string]any) {
			c["kms_key_id"] = "arn:aws-us-gov:kms:us-gov-west-1:111122223333:alias/example-root"
			c["secrets"] = map[string]any{"arn:aws-us-gov:secretsmanager:us-gov-west-1:111122223333:secret:example/ca-AbCdEf": s}
		}},
		{"partial secret ARN", func(c, s map[string]any) {
			c["secrets"] = map[string]any{strings.TrimSuffix(secretARN, "-AbCdEf"): s}
		}},
		{"each key type", func(c, s map[string]any) {
			secrets := map[string]any{}
			for i, kt := range []string{"ec-p256", "ec-p384", "rsa-2048", "rsa-4096"} {
				p := maps.Clone(s)
				p["key_type"] = kt
				secrets[fmt.Sprintf("%s%d", secretARN, i)] = p
			}
			c["secrets"] = secrets
		}},
		{"compound duration", func(_, s map[string]any) { s["validity"] = "2159h59m60s"; s["min_remaining"] = "1.5h" }},
		{"empty strings are defaults", func(c, s map[string]any) {
			c["signing_algorithm"] = ""
			s["key_type"], s["validity"], s["min_remaining"] = "", "", ""
		}},
		{"null is unset", func(_, s map[string]any) { s["max_path_len"], s["name_constraints"] = nil, nil }},
		{"every constraint list", func(_, s map[string]any) {
			s["name_constraints"] = map[string]any{
				"permitted_uri_domains": []string{"example.org"}, "excluded_uri_domains": []string{".example.org"},
				"permitted_dns_domains": []string{"example.org", "sub-1.example.org"}, "excluded_dns_domains": []string{".internal.example.org"},
			}
		}},
		// protobuf JSON also takes the lowerCamelCase names.
		{"lowerCamelCase names", func(c, s map[string]any) {
			c["kmsKeyId"] = c["kms_key_id"]
			delete(c, "kms_key_id")
			s["keyType"] = s["key_type"]
			delete(s, "key_type")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := config.Parse([]byte(document(t, rootPEM(t), tc.change))); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestParseRejects(t *testing.T) {
	root := rootPEM(t)
	for _, tc := range []struct {
		name    string
		change  func(cfg, secret map[string]any)
		wantErr []string
	}{
		// Durations.
		{"invalid duration", func(_, s map[string]any) { s["validity"] = "90 days" }, []string{".validity", "positive_duration"}},
		{"zero duration", func(_, s map[string]any) { s["validity"] = "0s" }, []string{".validity", "positive_duration"}},
		{"negative duration", func(_, s map[string]any) { s["validity"] = "-1h" }, []string{".validity", "positive_duration"}},
		{"unitless duration", func(_, s map[string]any) { s["validity"] = "3600" }, []string{".validity", "positive_duration"}},
		{"numeric duration", func(_, s map[string]any) { s["validity"] = 3600 }, []string{"validity"}},
		{"duration too long to represent", func(_, s map[string]any) { s["validity"] = "9999999999h" }, []string{"invalid"}},
		{"invalid min_remaining", func(_, s map[string]any) { s["min_remaining"] = "soon" }, []string{".min_remaining", "positive_duration"}},
		{"zero min_remaining", func(_, s map[string]any) { s["min_remaining"] = "0s" }, []string{".min_remaining", "positive_duration"}},
		{"min_remaining over validity", func(_, s map[string]any) { s["min_remaining"] = "721h" }, []string{"min_remaining_within_validity"}},
		{"min_remaining over the default validity", func(_, s map[string]any) {
			delete(s, "validity")
			s["min_remaining"] = "2161h"
		}, []string{"longer than validity 2160h"}},
		// Path length.
		{"path length too long for the root", func(_, s map[string]any) { s["max_path_len"] = 2 }, []string{"does not fit under the root's path length 2"}},
		{"negative path length", func(_, s map[string]any) { s["max_path_len"] = -1 }, []string{".max_path_len", "int32.gte_lte"}},
		{"path length over the cap", func(_, s map[string]any) { s["max_path_len"] = 9 }, []string{".max_path_len", "int32.gte_lte"}},
		{"fractional path length", func(_, s map[string]any) { s["max_path_len"] = 1.5 }, []string{"maxPathLen"}},
		// Key type and subject.
		{"unknown key type", func(_, s map[string]any) { s["key_type"] = "ed25519" }, []string{".key_type", "string.in"}},
		{"no subject", func(_, s map[string]any) { delete(s, "subject") }, []string{".subject", "required"}},
		{"no common name", func(_, s map[string]any) { s["subject"] = map[string]any{} }, []string{"common_name", "string.pattern"}},
		{"blank common name", func(_, s map[string]any) { s["subject"] = map[string]any{"common_name": " \t "} }, []string{"common_name", "string.pattern"}},
		{"common name too long", func(_, s map[string]any) {
			s["subject"] = map[string]any{"common_name": strings.Repeat("x", 65)}
		}, []string{"common_name", "string.max_len"}},
		// Name constraints.
		{"URI domain", func(_, s map[string]any) {
			s["name_constraints"] = map[string]any{"permitted_uri_domains": []string{"spiffe://example.org"}}
		}, []string{"permitted_uri_domains[0]", "string.pattern"}},
		{"empty domain", func(_, s map[string]any) {
			s["name_constraints"] = map[string]any{"excluded_dns_domains": []string{"example.org", ""}}
		}, []string{"excluded_dns_domains[1]", "string.pattern"}},
		{"wildcard domain", func(_, s map[string]any) {
			s["name_constraints"] = map[string]any{"permitted_dns_domains": []string{"*.example.org"}}
		}, []string{"permitted_dns_domains[0]"}},
		{"domain with a space", func(_, s map[string]any) {
			s["name_constraints"] = map[string]any{"excluded_uri_domains": []string{"example .org"}}
		}, []string{"excluded_uri_domains[0]"}},
		{"empty label", func(_, s map[string]any) {
			s["name_constraints"] = map[string]any{"permitted_uri_domains": []string{"example..org"}}
		}, []string{"permitted_uri_domains[0]"}},
		{"two leading dots", func(_, s map[string]any) {
			s["name_constraints"] = map[string]any{"permitted_uri_domains": []string{"..example.org"}}
		}, []string{"permitted_uri_domains[0]"}},
		// Unknown fields: a misspelt setting is not ignored, at any level.
		{"unknown field", func(_, s map[string]any) { s["validty"] = "1h" }, []string{"unknown field", "validty"}},
		{"unknown top-level field", func(c, _ map[string]any) { c["kms_key"] = "alias/example-root" }, []string{"unknown field", "kms_key"}},
		{"unknown subject field", func(_, s map[string]any) {
			s["subject"] = map[string]any{"common_name": "Example", "email": "ca@example.org"}
		}, []string{"unknown field", "email"}},
		{"unknown name constraints field", func(_, s map[string]any) {
			s["name_constraints"] = map[string]any{"permitted_ip_ranges": []string{"10.0.0.0/8"}}
		}, []string{"unknown field", "permitted_ip_ranges"}},
		// The KMS key and the signing algorithm.
		{"no kms key", func(c, _ map[string]any) { delete(c, "kms_key_id") }, []string{"kms_key_id", "required"}},
		{"kms key not an ID, ARN or alias", func(c, _ map[string]any) { c["kms_key_id"] = "example-root" }, []string{"kms_key_id", "string.pattern"}},
		{"kms key ARN of another service", func(c, _ map[string]any) {
			c["kms_key_id"] = "arn:aws:iam::111122223333:role/example"
		}, []string{"kms_key_id", "string.pattern"}},
		{"unknown signing algorithm", func(c, _ map[string]any) { c["signing_algorithm"] = "ECDSA_SHA_1" }, []string{"signing_algorithm", "string.in"}},
		// The root.
		{"no root", func(c, _ map[string]any) { delete(c, "root_certificate") }, []string{"root_certificate", "required"}},
		{"two roots", func(c, _ map[string]any) { c["root_certificate"] = root + root }, []string{"root_certificate", "exactly one"}},
		{"text after the root", func(c, _ map[string]any) { c["root_certificate"] = root + "trailing" }, []string{"root_certificate", "exactly one"}},
		{"text before the root", func(c, _ map[string]any) { c["root_certificate"] = "# root\n" + root }, []string{"root_certificate", "string.prefix"}},
		{"root not PEM", func(c, _ map[string]any) {
			c["root_certificate"] = "-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----\n"
		}, []string{"root_certificate", "not a PEM certificate"}},
		{"root not a certificate", func(c, _ map[string]any) {
			c["root_certificate"] = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
		}, []string{"root_certificate", "not an X.509 certificate"}},
		{"root too large", func(c, _ map[string]any) {
			c["root_certificate"] = root + strings.Repeat("\n", 16384)
		}, []string{"root_certificate", "string.max_bytes"}},
		{"root not a string", func(c, _ map[string]any) { c["root_certificate"] = []string{root} }, []string{"rootCertificate"}},
		// Secrets.
		{"no secrets", func(c, _ map[string]any) { c["secrets"] = map[string]any{} }, []string{"secrets", "map.min_pairs"}},
		{"secrets missing", func(c, _ map[string]any) { delete(c, "secrets") }, []string{"secrets", "map.min_pairs"}},
		{"not an ARN", func(c, s map[string]any) { c["secrets"] = map[string]any{"example": s} }, []string{`secrets["example"]`, "string.pattern"}},
		{"ARN of another service", func(c, s map[string]any) {
			c["secrets"] = map[string]any{"arn:aws:ssm:us-east-1:111122223333:parameter/example": s}
		}, []string{"string.pattern"}},
		{"secret ARN without a name", func(c, s map[string]any) {
			c["secrets"] = map[string]any{"arn:aws:secretsmanager:us-east-1:111122223333:secret:": s}
		}, []string{"string.pattern"}},
		{"secret not an object", func(c, _ map[string]any) { c["secrets"] = map[string]any{secretARN: "ec-p256"} }, []string{"unexpected token"}},
		{"certificate where an object belongs", func(c, _ map[string]any) {
			c["secrets"] = map[string]any{secretARN: root}
		}, []string{"a certificate where another value belongs"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := config.Parse([]byte(document(t, root, tc.change)))
			if err == nil {
				t.Fatalf("Parse = nil, want an error with %q", tc.wantErr)
			}
			for _, want := range tc.wantErr {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("Parse = %v, want an error with %q", err, want)
				}
			}
			t.Log(err)
			noCertificate(t, err, root)
		})
	}
}

// The document must be one JSON object and nothing else.
func TestParseRejectsJSON(t *testing.T) {
	doc := document(t, rootPEM(t), nil)
	for name, data := range map[string]string{
		"trailing data":   doc + `{}`,
		"not JSON":        "kms_key_id: alias/example-root",
		"an array":        "[" + doc + "]",
		"duplicate field": strings.Replace(doc, `"kms_key_id":`, `"kms_key_id":"alias/other","kms_key_id":`, 1),
		"empty":           "",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := config.Parse([]byte(data)); err == nil {
				t.Fatal("Parse = nil, want an error")
			}
		})
	}
}

// noCertificate fails if err holds any part of the root certificate's PEM
// body. (The PEM header can be in an error: the rule for root_certificate
// names it as the prefix it wants.)
func noCertificate(t *testing.T, err error, root string) {
	t.Helper()
	msg := err.Error()
	for line := range strings.Lines(root) {
		if line = strings.TrimSpace(line); len(line) >= 16 && !strings.HasPrefix(line, "-----") && strings.Contains(msg, line[:16]) {
			t.Fatalf("the error holds the certificate: %v", err)
		}
	}
}

// The example configuration in the README parses, with a real certificate
// in place of its placeholder.
func TestREADMEExample(t *testing.T) {
	readme, err := os.ReadFile("../README.md")
	if err != nil {
		t.Fatal(err)
	}
	_, section, ok := strings.Cut(string(readme), "\n## Configuration\n")
	if !ok {
		t.Fatal("README.md has no Configuration section")
	}
	_, block, ok := strings.Cut(section, "```json\n")
	if !ok {
		t.Fatal("README.md's Configuration section has no JSON example")
	}
	block, _, _ = strings.Cut(block, "```")
	var doc map[string]any
	if err := json.Unmarshal([]byte(block), &doc); err != nil {
		t.Fatalf("the README example is not JSON: %v", err)
	}
	if !strings.HasPrefix(doc["root_certificate"].(string), "-----BEGIN CERTIFICATE-----") {
		t.Fatal("the README example has no root_certificate placeholder")
	}
	doc["root_certificate"] = rootPEM(t)
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse(data)
	if err != nil {
		t.Fatalf("the README example: %v", err)
	}
	if len(cfg.Secrets) != 1 {
		t.Fatalf("the README example has %d secrets, want 1", len(cfg.Secrets))
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

// The root must leave room for the intermediate and its path length.
func TestParseRootPathLength(t *testing.T) {
	root := func(change func(*x509.Certificate)) string {
		return testca.NewRootWith(t, testca.NewKey(t, elliptic.P384()), time.Hour, change).PEM()
	}
	pathLen := func(n int) func(*x509.Certificate) {
		return func(c *x509.Certificate) { c.MaxPathLen, c.MaxPathLenZero = n, n == 0 }
	}
	for _, tc := range []struct {
		name       string
		root       string
		maxPathLen int
		wantErr    string // empty: valid
	}{
		{"root 0", root(pathLen(0)), 0, "can issue no intermediate CA"},
		{"root 1, intermediate 1", root(pathLen(1)), 1, "does not fit"},
		{"root 1, intermediate 0", root(pathLen(1)), 0, ""},
		{"root 3, intermediate 2", root(pathLen(3)), 2, ""},
		{"unconstrained root", root(pathLen(-1)), 5, ""},
		{"root without keyCertSign", root(func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageDigitalSignature }), 0, "keyCertSign"},
		{"root not a CA", root(func(c *x509.Certificate) { c.IsCA, c.MaxPathLen, c.MaxPathLenZero = false, 0, false }), 0, "not a CA certificate"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := config.Parse([]byte(document(t, tc.root, func(_, s map[string]any) { s["max_path_len"] = tc.maxPathLen })))
			if tc.wantErr == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Parse = %v, want an error with %q", err, tc.wantErr)
			}
		})
	}
}
