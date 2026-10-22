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

	"github.com/bpalermo/kms-intermediate-rotator/internal/testca"
	"github.com/bpalermo/kms-intermediate-rotator/pkg/intermediate"
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
	root := testca.NewRoot(t, testca.NewKey(t, elliptic.P384()), rootLifetime)
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
			if err := intermediate.Check(c, p, now, 0); err != nil {
				t.Errorf("Check: %v", err)
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
	if err := intermediate.Check(got.cert, p, time.Now(), 0); err != nil {
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

// The name constraints work in Go's verifier: a leaf under the
// intermediate with a URI SAN in the permitted domain verifies, one outside
// it or in an excluded domain does not.
func TestNameConstraintsEnforced(t *testing.T) {
	got := issue(t, profile(), 24*365*time.Hour, time.Now())
	for _, tc := range []struct {
		uri  string
		want bool
	}{
		{"spiffe://example.org/workload", true},
		{"spiffe://other.example.net/workload", false},
		{"spiffe://bad.example.org/workload", false},
	} {
		t.Run(tc.uri, func(t *testing.T) {
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
	now := time.Now()
	good := profile()
	got := issue(t, good, 10*365*24*time.Hour, now)
	for _, tc := range []struct {
		name   string
		modify func(*intermediate.Profile)
		now    time.Time
	}{
		{"other subject", func(p *intermediate.Profile) { p.Subject.CommonName = "Other" }, now},
		{"other key type", func(p *intermediate.Profile) { p.KeyType = intermediate.KeyTypeECP384 }, now},
		{"other path length", func(p *intermediate.Profile) { p.MaxPathLen = 0 }, now},
		{"missing permitted URI domain", func(p *intermediate.Profile) {
			p.NameConstraints.PermittedURIDomains = append(p.NameConstraints.PermittedURIDomains, "example.net")
		}, now},
		{"other excluded DNS domain", func(p *intermediate.Profile) { p.NameConstraints.ExcludedDNSDomains = nil }, now},
		{"too short", func(*intermediate.Profile) {}, now.Add(48 * time.Hour)},
		{"longer validity configured", func(p *intermediate.Profile) { p.Validity *= 2 }, now},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := profile()
			tc.modify(&p)
			if err := intermediate.Check(got.cert, p, tc.now, 24*time.Hour); err == nil {
				t.Fatal("Check succeeded, want an error")
			}
		})
	}
	if err := intermediate.Check(got.cert, good, now.Add(23*time.Hour), 24*time.Hour); err != nil {
		t.Fatalf("Check within the slack: %v", err)
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
