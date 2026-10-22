package secretformat_test

import (
	"crypto/elliptic"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/bpalermo/kms-intermediate-rotator/intermediate"
	"github.com/bpalermo/kms-intermediate-rotator/internal/testca"
	"github.com/bpalermo/kms-intermediate-rotator/secretformat"
)

type fixture struct {
	root     *testca.Root
	bundle   *secretformat.Bundle
	otherKey string
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	root := testca.NewRoot(t, testca.NewKey(t, elliptic.P384()), 365*24*time.Hour)
	key, err := intermediate.GenerateKey(intermediate.KeyTypeECP256)
	if err != nil {
		t.Fatal(err)
	}
	p := intermediate.Profile{
		Subject:    pkix.Name{CommonName: "Example Intermediate CA"},
		KeyType:    intermediate.KeyTypeECP256,
		Validity:   24 * time.Hour,
		MaxPathLen: 0,
	}
	cert, err := intermediate.Issue(p, key.Public(), root.Cert, root.Key, x509.UnknownSignatureAlgorithm, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	other, _ := intermediate.GenerateKey(intermediate.KeyTypeECP256)
	otherSecret, err := secretformat.Encode(&secretformat.Bundle{Cert: cert, Key: other, Root: root.Cert})
	if err != nil {
		t.Fatal(err)
	}
	return fixture{root: root, bundle: &secretformat.Bundle{Cert: cert, Key: key, Root: root.Cert}, otherKey: field(t, otherSecret, "key")}
}

func field(t *testing.T, secret, name string) string {
	t.Helper()
	var m map[string]string
	if err := json.Unmarshal([]byte(secret), &m); err != nil {
		t.Fatal(err)
	}
	return m[name]
}

func edit(t *testing.T, secret string, change func(map[string]any)) string {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(secret), &m); err != nil {
		t.Fatal(err)
	}
	change(m)
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func TestRoundTrip(t *testing.T) {
	f := newFixture(t)
	s, err := secretformat.Encode(f.bundle)
	if err != nil {
		t.Fatal(err)
	}
	if got := field(t, s, "format"); got != "intermediate-ca/v1" {
		t.Fatalf("format %q", got)
	}
	if got := field(t, s, "chain"); got != "" {
		t.Fatalf("chain %q, want empty", got)
	}
	if !strings.HasPrefix(field(t, s, "key"), "-----BEGIN PRIVATE KEY-----\n") {
		t.Fatal("key is not PKCS#8 PEM")
	}
	b, err := secretformat.Decode(s, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !b.Cert.Equal(f.bundle.Cert) || !b.Root.Equal(f.bundle.Root) || len(b.Chain) != 0 {
		t.Fatal("decoded bundle differs")
	}
	// Unknown fields are ignored.
	extra := edit(t, s, func(m map[string]any) { m["comment"] = "ignored" })
	if _, err := secretformat.Decode(extra, time.Now()); err != nil {
		t.Fatalf("unknown field: %v", err)
	}
}

// A chain of one more CA between the intermediate and the root verifies.
func TestDecodeWithChain(t *testing.T) {
	f := newFixture(t)
	root := testca.NewRoot(t, testca.NewKey(t, elliptic.P384()), 365*24*time.Hour)
	// f's root, re-issued under the new root, is the chain.
	p := intermediate.Profile{Subject: f.root.Cert.Subject, KeyType: intermediate.KeyTypeECP384, Validity: 48 * time.Hour, MaxPathLen: 1}
	mid, err := intermediate.Issue(p, f.root.Key.Public(), root.Cert, root.Key, x509.UnknownSignatureAlgorithm, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	b := &secretformat.Bundle{Cert: f.bundle.Cert, Key: f.bundle.Key, Chain: []*x509.Certificate{mid}, Root: root.Cert}
	s, err := secretformat.Encode(b)
	if err != nil {
		t.Fatal(err)
	}
	got, err := secretformat.Decode(s, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Chain) != 1 || !got.Chain[0].Equal(mid) {
		t.Fatal("chain not decoded")
	}
}

func TestDecodeRejects(t *testing.T) {
	f := newFixture(t)
	good, err := secretformat.Encode(f.bundle)
	if err != nil {
		t.Fatal(err)
	}
	otherRoot := testca.NewRoot(t, testca.NewKey(t, elliptic.P384()), time.Hour)
	cert := field(t, good, "cert")
	for _, tc := range []struct {
		name   string
		secret string
		now    time.Time
	}{
		{"not json", "-----BEGIN CERTIFICATE-----", time.Now()},
		{"unknown format", edit(t, good, func(m map[string]any) { m["format"] = "intermediate-ca/v2" }), time.Now()},
		{"no format", edit(t, good, func(m map[string]any) { delete(m, "format") }), time.Now()},
		{"two certs", edit(t, good, func(m map[string]any) { m["cert"] = cert + cert }), time.Now()},
		{"no cert", edit(t, good, func(m map[string]any) { m["cert"] = "" }), time.Now()},
		{"key of another cert", edit(t, good, func(m map[string]any) { m["key"] = f.otherKey }), time.Now()},
		{"key not PKCS#8", edit(t, good, func(m map[string]any) {
			m["key"] = strings.ReplaceAll(f.otherKey, "PRIVATE KEY", "EC PRIVATE KEY")
		}), time.Now()},
		{"other root", edit(t, good, func(m map[string]any) { m["root"] = otherRoot.PEM() }), time.Now()},
		{"garbage in chain", edit(t, good, func(m map[string]any) { m["chain"] = cert + "garbage" }), time.Now()},
		{"expired", good, time.Now().Add(48 * time.Hour)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := secretformat.Decode(tc.secret, tc.now); err == nil {
				t.Fatal("Decode succeeded, want an error")
			}
		})
	}
}
