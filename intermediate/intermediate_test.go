package intermediate_test

import (
	"bytes"
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"net/url"
	"slices"
	"testing"
	"time"

	"github.com/bpalermo/kms-intermediate-rotator/intermediate"
	"github.com/bpalermo/kms-intermediate-rotator/internal/testca"
)

var (
	oidBasicConstraints = asn1.ObjectIdentifier{2, 5, 29, 19}
	oidKeyUsage         = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidNameConstraints  = asn1.ObjectIdentifier{2, 5, 29, 30}
)

func profile() intermediate.Profile {
	return intermediate.Profile{
		Subject: pkix.Name{
			CommonName:   "Example Intermediate CA",
			Organization: []string{"Example"},
			Country:      []string{"US"},
		},
		KeyType:    intermediate.KeyTypeECP256,
		Validity:   2160 * time.Hour,
		MaxPathLen: 1,
		NameConstraints: intermediate.NameConstraints{
			PermittedURIDomains: []string{"example.org"},
			ExcludedURIDomains:  []string{"bad.example.org"},
			PermittedDNSDomains: []string{".example.org"},
			ExcludedDNSDomains:  []string{"internal.example.org"},
		},
	}
}

type issued struct {
	root *testca.Root
	key  crypto.Signer
	cert *x509.Certificate
}

func issue(t *testing.T, p intermediate.Profile, rootLifetime time.Duration, now time.Time) issued {
	t.Helper()
	return issueUnder(t, p, testca.NewRoot(t, testca.NewKey(t, elliptic.P384()), rootLifetime), now)
}

func issueUnder(t *testing.T, p intermediate.Profile, root *testca.Root, now time.Time) issued {
	t.Helper()
	key, err := intermediate.GenerateKey(p.KeyType)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := intermediate.Issue(p, key.Public(), root.Cert, root.Key, x509.UnknownSignatureAlgorithm, now)
	if err != nil {
		t.Fatal(err)
	}
	return issued{root: root, key: key, cert: cert}
}

func extension(t *testing.T, c *x509.Certificate, oid asn1.ObjectIdentifier) (pkix.Extension, bool) {
	t.Helper()
	for _, e := range c.Extensions {
		if e.Id.Equal(oid) {
			return e, true
		}
	}
	return pkix.Extension{}, false
}

func TestIssue(t *testing.T) {
	now := time.Now()
	for _, tc := range []struct {
		name       string
		maxPathLen int
		keyType    intermediate.KeyType
	}{
		{"path length 1", 1, intermediate.KeyTypeECP256},
		{"path length 0", 0, intermediate.KeyTypeECP384},
		{"path length 3 rsa", 3, intermediate.KeyTypeRSA2048},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := profile()
			p.MaxPathLen = tc.maxPathLen
			p.KeyType = tc.keyType
			got := issue(t, p, 10*365*24*time.Hour, now)
			c := got.cert

			wantSubject, _ := asn1.Marshal(p.Subject.ToRDNSequence())
			if !bytes.Equal(c.RawSubject, wantSubject) {
				t.Errorf("subject %s, want %s", c.Subject, p.Subject)
			}
			if !c.IsCA || !c.BasicConstraintsValid || c.MaxPathLen != tc.maxPathLen || c.MaxPathLenZero != (tc.maxPathLen == 0) {
				t.Errorf("basic constraints CA=%t pathlen=%d zero=%t", c.IsCA, c.MaxPathLen, c.MaxPathLenZero)
			}
			if c.KeyUsage != x509.KeyUsageCertSign|x509.KeyUsageCRLSign {
				t.Errorf("key usage %#x", c.KeyUsage)
			}
			for name, oid := range map[string]asn1.ObjectIdentifier{
				"basic constraints": oidBasicConstraints,
				"key usage":         oidKeyUsage,
				"name constraints":  oidNameConstraints,
			} {
				if e, ok := extension(t, c, oid); !ok || !e.Critical {
					t.Errorf("%s: present=%t, want present and critical", name, ok)
				}
			}
			nc := p.NameConstraints
			if !slices.Equal(c.PermittedURIDomains, nc.PermittedURIDomains) || !slices.Equal(c.ExcludedURIDomains, nc.ExcludedURIDomains) ||
				!slices.Equal(c.PermittedDNSDomains, nc.PermittedDNSDomains) || !slices.Equal(c.ExcludedDNSDomains, nc.ExcludedDNSDomains) {
				t.Errorf("name constraints %v %v %v %v", c.PermittedURIDomains, c.ExcludedURIDomains, c.PermittedDNSDomains, c.ExcludedDNSDomains)
			}
			if want := now.Add(p.Validity).Truncate(time.Second); !c.NotAfter.Equal(want) {
				t.Errorf("not after %s, want %s", c.NotAfter, want)
			}
			if want := now.Add(-intermediate.Backdate).Truncate(time.Second); !c.NotBefore.Equal(want) {
				t.Errorf("not before %s, want %s", c.NotBefore, want)
			}
			ski, _ := intermediate.SubjectKeyID(got.key.Public())
			if !bytes.Equal(c.SubjectKeyId, ski) || len(ski) != 20 {
				t.Errorf("subject key id %x, want %x", c.SubjectKeyId, ski)
			}
			if !bytes.Equal(c.AuthorityKeyId, got.root.Cert.SubjectKeyId) || len(c.AuthorityKeyId) == 0 {
				t.Errorf("authority key id %x, want the root's %x", c.AuthorityKeyId, got.root.Cert.SubjectKeyId)
			}
			if c.SerialNumber.Sign() <= 0 || c.SerialNumber.BitLen() > 128 {
				t.Errorf("serial %s", c.SerialNumber)
			}
			if err := intermediate.Check(c, p); err != nil {
				t.Errorf("Check: %v", err)
			}
			if err := intermediate.CheckLifetime(c, p, got.root.Cert, now); err != nil {
				t.Errorf("CheckLifetime: %v", err)
			}
			if err := intermediate.VerifyDepth(c, got.key, got.root.Cert, now); tc.maxPathLen <= 1 && err != nil {
				t.Errorf("VerifyDepth: %v", err)
			}
			verifyChain(t, c, got.root.Cert, nil)
		})
	}
}

func verifyChain(t *testing.T, leaf, root *x509.Certificate, inter *x509.Certificate) {
	t.Helper()
	if err := verifyErr(leaf, root, inter); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func verifyErr(leaf, root, inter *x509.Certificate) error {
	roots := x509.NewCertPool()
	roots.AddCert(root)
	inters := x509.NewCertPool()
	if inter != nil {
		inters.AddCert(inter)
	}
	_, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inters, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	return err
}

// Without name constraints, the extension is left out.
func TestIssueNoNameConstraints(t *testing.T) {
	p := profile()
	p.NameConstraints = intermediate.NameConstraints{}
	got := issue(t, p, 24*365*time.Hour, time.Now())
	if _, ok := extension(t, got.cert, oidNameConstraints); ok {
		t.Fatal("name constraints extension present")
	}
	if err := intermediate.Check(got.cert, p); err != nil {
		t.Fatal(err)
	}
}

func TestIssueCapsAtRootNotAfter(t *testing.T) {
	now := time.Now()
	got := issue(t, profile(), 30*24*time.Hour, now)
	if !got.cert.NotAfter.Equal(got.root.Cert.NotAfter) {
		t.Fatalf("not after %s, want the root's %s", got.cert.NotAfter, got.root.Cert.NotAfter)
	}
}

func TestIssueRefusesExpiredRoot(t *testing.T) {
	root := testca.NewRoot(t, testca.NewKey(t, elliptic.P384()), time.Hour)
	key, _ := intermediate.GenerateKey(intermediate.KeyTypeECP256)
	if _, err := intermediate.Issue(profile(), key.Public(), root.Cert, root.Key, x509.UnknownSignatureAlgorithm, time.Now().Add(2*time.Hour)); err == nil {
		t.Fatal("Issue succeeded after the root expired")
	}
}

// The name constraints work in Go's verifier, with Go's reading of a
// constraint without a leading dot: that host and every host below it.
func TestNameConstraintsEnforced(t *testing.T) {
	pairing := profile()
	pairing.NameConstraints = intermediate.NameConstraints{
		PermittedURIDomains: []string{"example.org"},
		ExcludedURIDomains:  []string{".example.org"},
	}
	for _, tc := range []struct {
		name    string
		profile intermediate.Profile
		uri     string
		want    bool
	}{
		{"permitted host", profile(), "spiffe://example.org/workload", true},
		{"other domain", profile(), "spiffe://other.example.net/workload", false},
		{"excluded subdomain", profile(), "spiffe://bad.example.org/workload", false},
		// Go, unlike RFC 5280 and OpenSSL for URIs, lets "example.org"
		// permit its subdomains.
		{"subdomain, Go reading", profile(), "spiffe://sub.example.org/workload", true},
		// Permitting "example.org" and excluding ".example.org" is host-only
		// in Go as in OpenSSL.
		{"pairing: exact host", pairing, "spiffe://example.org/workload", true},
		{"pairing: subdomain", pairing, "spiffe://sub.example.org/workload", false},
		{"pairing: other domain", pairing, "spiffe://example.net/workload", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := issue(t, tc.profile, 24*365*time.Hour, time.Now())
			leaf := issueLeaf(t, got, tc.uri)
			err := verifyErr(leaf, got.root.Cert, got.cert)
			if tc.want && err != nil {
				t.Fatalf("verify: %v", err)
			}
			if !tc.want {
				var invalid x509.CertificateInvalidError
				if !errors.As(err, &invalid) || invalid.Reason != x509.CANotAuthorizedForThisName {
					t.Fatalf("verify = %v, want CANotAuthorizedForThisName", err)
				}
			}
		})
	}
}

func issueLeaf(t *testing.T, ca issued, uri string) *x509.Certificate {
	t.Helper()
	u, err := url.Parse(uri)
	if err != nil {
		t.Fatal(err)
	}
	key := testca.NewKey(t, elliptic.P256())
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		URIs:         []*url.URL{u},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, key.Public(), ca.key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return leaf
}

func TestCheckRejects(t *testing.T) {
	got := issue(t, profile(), 10*365*24*time.Hour, time.Now())
	for _, tc := range []struct {
		name   string
		modify func(*intermediate.Profile)
	}{
		{"other subject", func(p *intermediate.Profile) { p.Subject.CommonName = "Other" }},
		{"other key type", func(p *intermediate.Profile) { p.KeyType = intermediate.KeyTypeECP384 }},
		{"other path length", func(p *intermediate.Profile) { p.MaxPathLen = 0 }},
		{"missing permitted URI domain", func(p *intermediate.Profile) {
			p.NameConstraints.PermittedURIDomains = append(p.NameConstraints.PermittedURIDomains, "example.net")
		}},
		{"other excluded DNS domain", func(p *intermediate.Profile) { p.NameConstraints.ExcludedDNSDomains = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := profile()
			tc.modify(&p)
			if err := intermediate.Check(got.cert, p); err == nil {
				t.Fatal("Check succeeded, want an error")
			}
		})
	}
}

// The lifetime is judged from the issuance, so a pending intermediate
// checked days after it was issued still passes while enough of it is left.
func TestCheckLifetime(t *testing.T) {
	issuedAt := time.Now()
	day := 24 * time.Hour
	longRoot := testca.NewRoot(t, testca.NewKey(t, elliptic.P384()), 10*365*day)
	shortRoot := testca.NewRoot(t, testca.NewKey(t, elliptic.P384()), 30*day)
	short := profile()
	short.Validity = 10 * day
	for _, tc := range []struct {
		name     string
		issuedAs intermediate.Profile
		root     *testca.Root
		checkAs  func(*intermediate.Profile)
		at       time.Duration // after issuance
		wantErr  error         // nil: passes; errAny: any error
	}{
		{"right away", profile(), longRoot, nil, 0, nil},
		{"a day later", profile(), longRoot, nil, day, nil},
		{"a week later", profile(), longRoot, nil, 7 * day, nil},
		{"at half the validity", profile(), longRoot, nil, 45*day - time.Minute, nil},
		{"most of the validity later", profile(), longRoot, nil, 80 * day, intermediate.ErrTooLittleLeft},
		{"custom minimum remaining", profile(), longRoot, func(p *intermediate.Profile) { p.MinRemaining = 5 * day }, 80 * day, nil},
		{"issued shorter than configured", short, longRoot, nil, 0, errAny},
		{"configured longer since", profile(), longRoot, func(p *intermediate.Profile) { p.Validity *= 2 }, 0, errAny},
		{"capped at the root, enough left", profile(), shortRoot, func(p *intermediate.Profile) { p.MinRemaining = 7 * day }, day, nil},
		{"capped at the root, too little left", profile(), shortRoot, nil, day, intermediate.ErrTooLittleLeft},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := issueUnder(t, tc.issuedAs, tc.root, issuedAt)
			p := profile()
			if tc.checkAs != nil {
				tc.checkAs(&p)
			}
			err := intermediate.CheckLifetime(got.cert, p, tc.root.Cert, issuedAt.Add(tc.at))
			switch {
			case tc.wantErr == nil && err != nil:
				t.Fatalf("CheckLifetime: %v", err)
			case tc.wantErr == errAny && err == nil:
				t.Fatal("CheckLifetime succeeded, want an error")
			case tc.wantErr != nil && tc.wantErr != errAny && !errors.Is(err, tc.wantErr):
				t.Fatalf("CheckLifetime = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

var errAny = errors.New("any error")

// A path length the root leaves no room for verifies alone, and fails
// VerifyDepth.
func TestVerifyDepth(t *testing.T) {
	rootWith := func(pathLen int) *testca.Root {
		return testca.NewRootWith(t, testca.NewKey(t, elliptic.P384()), 365*24*time.Hour, func(c *x509.Certificate) {
			c.MaxPathLen, c.MaxPathLenZero = pathLen, pathLen == 0
		})
	}
	for _, tc := range []struct {
		name       string
		rootPath   int // -1: unconstrained
		maxPathLen int
		want       bool
	}{
		{"root 2, intermediate 0", 2, 0, true},
		{"root 2, intermediate 1", 2, 1, true},
		{"root 2, intermediate 2", 2, 2, false},
		{"root 1, intermediate 1", 1, 1, false},
		{"unconstrained root, intermediate 3", -1, 3, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := profile()
			p.MaxPathLen = tc.maxPathLen
			root := rootWith(tc.rootPath)
			now := time.Now()
			got := issueUnder(t, p, root, now)
			verifyChain(t, got.cert, root.Cert, nil) // alone, it always verifies
			err := intermediate.VerifyDepth(got.cert, got.key, root.Cert, now)
			if tc.want && err != nil {
				t.Fatalf("VerifyDepth: %v", err)
			}
			if !tc.want {
				var invalid x509.CertificateInvalidError
				if !errors.As(err, &invalid) || invalid.Reason != x509.TooManyIntermediates {
					t.Fatalf("VerifyDepth = %v, want TooManyIntermediates", err)
				}
			}
		})
	}
}

func TestKeyType(t *testing.T) {
	for _, kt := range []intermediate.KeyType{intermediate.KeyTypeECP256, intermediate.KeyTypeECP384, intermediate.KeyTypeRSA2048} {
		k, err := intermediate.GenerateKey(kt)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := intermediate.KeyTypeOf(k.Public()); err != nil || got != kt {
			t.Fatalf("KeyTypeOf(%s) = %s, %v", kt, got, err)
		}
	}
	if intermediate.KeyType("ed25519").Valid() {
		t.Fatal("ed25519 is not a key type")
	}
	if _, err := intermediate.GenerateKey("ed25519"); err == nil {
		t.Fatal("GenerateKey(ed25519) succeeded")
	}
}
