// Package testca makes throwaway root CAs for tests: a real key and a
// self-signed root certificate, in memory. For tests only.
package testca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// Root is a root CA.
type Root struct {
	Key  crypto.Signer
	Cert *x509.Certificate
}

// PEM is the root certificate, PEM-encoded.
func (r *Root) PEM() string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: r.Cert.Raw}))
}

// NewKey returns a new ECDSA key on curve.
func NewKey(t testing.TB, curve elliptic.Curve) crypto.Signer {
	t.Helper()
	k, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// NewRoot returns a self-signed root for key, valid from an hour ago for
// lifetime, with path length 2 and a SubjectKeyId.
func NewRoot(t testing.TB, key crypto.Signer, lifetime time.Duration) *Root {
	t.Helper()
	return NewRootWith(t, key, lifetime, nil)
}

// NewRootWith is NewRoot with change applied to the template before it is
// signed.
func NewRootWith(t testing.TB, key crypto.Signer, lifetime time.Duration, change func(*x509.Certificate)) *Root {
	t.Helper()
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Example Root CA", Organization: []string{"Example"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(lifetime),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            2,
	}
	if change != nil {
		change(tmpl)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &Root{Key: key, Cert: cert}
}
