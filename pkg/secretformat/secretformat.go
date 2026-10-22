// Package secretformat encodes, decodes and validates the secret format v1
// (`intermediate-ca/v1`, docs/secret-format.md): the JSON SecretString that
// holds an intermediate CA, its private key, the chain to the root and the
// root.
package secretformat

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"
)

// FormatV1 is the value of the "format" field of a v1 secret.
const FormatV1 = "intermediate-ca/v1"

// The PEM block types of the format.
const (
	blockCertificate = "CERTIFICATE"
	blockPrivateKey  = "PRIVATE KEY"
)

// wire is the JSON of a v1 secret. Unknown fields are ignored.
type wire struct {
	Format string `json:"format"`
	Cert   string `json:"cert"`
	Key    string `json:"key"`
	Chain  string `json:"chain"`
	Root   string `json:"root"`
}

// Bundle is a decoded v1 secret.
type Bundle struct {
	// Cert is the intermediate CA.
	Cert *x509.Certificate
	// Key is Cert's private key.
	Key crypto.Signer
	// Chain are the certificates between Cert and Root, Cert's issuer
	// first; empty when Root issued Cert.
	Chain []*x509.Certificate
	// Root is the trust anchor.
	Root *x509.Certificate
}

// Encode returns b as a v1 SecretString. It does not validate b; call
// Verify first.
func Encode(b *Bundle) (string, error) {
	if b == nil || b.Cert == nil || b.Key == nil || b.Root == nil {
		return "", errors.New("encode: cert, key and root are required")
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(b.Key)
	if err != nil {
		return "", fmt.Errorf("encode the private key: %w", err)
	}
	var chain strings.Builder
	for _, c := range b.Chain {
		chain.Write(certPEM(c))
	}
	out, err := json.Marshal(wire{
		Format: FormatV1,
		Cert:   string(certPEM(b.Cert)),
		Key:    string(pem.EncodeToMemory(&pem.Block{Type: blockPrivateKey, Bytes: keyDER})),
		Chain:  chain.String(),
		Root:   string(certPEM(b.Root)),
	})
	if err != nil {
		return "", fmt.Errorf("encode: %w", err)
	}
	return string(out), nil
}

// Decode parses a v1 SecretString and verifies it at now (see Verify). This
// is what a reader of the format must do.
func Decode(secret string, now time.Time) (*Bundle, error) {
	b, err := Parse(secret)
	if err != nil {
		return nil, err
	}
	if err := b.Verify(now); err != nil {
		return nil, err
	}
	return b, nil
}

// Parse parses a v1 SecretString without verifying it: an unknown format,
// a cert or root that is not exactly one certificate, a key that is not
// exactly one PKCS#8 private key, or a chain with anything but certificates
// are errors.
func Parse(secret string) (*Bundle, error) {
	var w wire
	if err := json.Unmarshal([]byte(secret), &w); err != nil {
		return nil, fmt.Errorf("secret is not JSON: %w", err)
	}
	if w.Format != FormatV1 {
		return nil, fmt.Errorf("unknown secret format %q, want %q", w.Format, FormatV1)
	}
	cert, err := ParseOneCertificate(w.Cert)
	if err != nil {
		return nil, fmt.Errorf("cert: %w", err)
	}
	key, err := parseKey(w.Key)
	if err != nil {
		return nil, fmt.Errorf("key: %w", err)
	}
	chain, err := ParseCertificates(w.Chain)
	if err != nil {
		return nil, fmt.Errorf("chain: %w", err)
	}
	root, err := ParseOneCertificate(w.Root)
	if err != nil {
		return nil, fmt.Errorf("root: %w", err)
	}
	return &Bundle{Cert: cert, Key: key, Chain: chain, Root: root}, nil
}

// Verify checks that b's key is the private key of b's cert and that the
// cert verifies to the root through the chain at now.
func (b *Bundle) Verify(now time.Time) error {
	pub, ok := b.Cert.PublicKey.(interface{ Equal(crypto.PublicKey) bool })
	if !ok || !pub.Equal(b.Key.Public()) {
		return errors.New("the key does not match the cert's public key")
	}
	roots := x509.NewCertPool()
	roots.AddCert(b.Root)
	intermediates := x509.NewCertPool()
	for _, c := range b.Chain {
		intermediates.AddCert(c)
	}
	_, err := b.Cert.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return fmt.Errorf("the cert does not verify to the root: %w", err)
	}
	return nil
}

// ParseCertificates parses zero or more PEM certificates. Any other PEM
// block, or text that is not PEM, is an error.
func ParseCertificates(s string) ([]*x509.Certificate, error) {
	rest := []byte(s)
	var certs []*x509.Certificate
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != blockCertificate {
			return nil, fmt.Errorf("unexpected PEM block %q", block.Type)
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, c)
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("trailing data that is not a PEM certificate")
	}
	return certs, nil
}

// ParseOneCertificate parses exactly one PEM certificate.
func ParseOneCertificate(s string) (*x509.Certificate, error) {
	certs, err := ParseCertificates(s)
	if err != nil {
		return nil, err
	}
	if len(certs) != 1 {
		return nil, fmt.Errorf("%d certificates, want exactly one", len(certs))
	}
	return certs[0], nil
}

func parseKey(s string) (crypto.Signer, error) {
	block, rest := pem.Decode([]byte(s))
	if block == nil {
		return nil, errors.New("no PEM block")
	}
	if block.Type != blockPrivateKey {
		return nil, fmt.Errorf("PEM block %q, want %q (PKCS#8)", block.Type, blockPrivateKey)
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("trailing data after the key")
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	signer, ok := k.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("unsupported private key %T", k)
	}
	return signer, nil
}

func certPEM(c *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: blockCertificate, Bytes: c.Raw})
}
