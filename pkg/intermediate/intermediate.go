// Package intermediate builds, issues and checks the intermediate CA
// certificate the rotator keeps in a secret. Everything in the certificate
// comes from a Profile (the per-secret configuration) and the root; nothing
// comes from a request.
package intermediate

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"slices"
	"time"
)

// Backdate is how far before the issuance time the certificate's NotBefore
// is set, to absorb clock skew between the rotator and the relying parties.
const Backdate = 5 * time.Minute

// NameConstraints are the name constraints written into the intermediate.
// URI domains follow Go's crypto/x509 semantics: "example.org" matches that
// host only, ".example.org" any host below it.
type NameConstraints struct {
	PermittedURIDomains []string
	ExcludedURIDomains  []string
	PermittedDNSDomains []string
	ExcludedDNSDomains  []string
}

// Empty reports whether no constraint is set.
func (n NameConstraints) Empty() bool {
	return len(n.PermittedURIDomains) == 0 && len(n.ExcludedURIDomains) == 0 &&
		len(n.PermittedDNSDomains) == 0 && len(n.ExcludedDNSDomains) == 0
}

// Profile is what an intermediate is made of: everything but its key, its
// serial number and its validity window, which are chosen at issuance.
type Profile struct {
	Subject pkix.Name
	// KeyType is the type of key generated for the intermediate.
	KeyType KeyType
	// Validity is how long a new intermediate is valid for, capped at the
	// root's NotAfter.
	Validity time.Duration
	// MaxPathLen is the path length constraint; 0 is a real constraint
	// (written with MaxPathLenZero), never "unset".
	MaxPathLen      int
	NameConstraints NameConstraints
}

// Template returns the certificate template for a new intermediate with the
// public key pub, issued by root at now.
func Template(p Profile, pub crypto.PublicKey, root *x509.Certificate, now time.Time) (*x509.Certificate, error) {
	if p.Validity <= 0 {
		return nil, fmt.Errorf("validity %s is not positive", p.Validity)
	}
	if p.MaxPathLen < 0 {
		return nil, fmt.Errorf("max path length %d is negative", p.MaxPathLen)
	}
	notBefore := now.Add(-Backdate)
	notAfter := now.Add(p.Validity)
	if notAfter.After(root.NotAfter) {
		notAfter = root.NotAfter
	}
	if !notAfter.After(now) {
		return nil, fmt.Errorf("the root expires at %s: no validity left", root.NotAfter.UTC().Format(time.RFC3339))
	}
	serial, err := SerialNumber(rand.Reader)
	if err != nil {
		return nil, err
	}
	ski, err := SubjectKeyID(pub)
	if err != nil {
		return nil, err
	}
	aki := root.SubjectKeyId
	if len(aki) == 0 {
		// A root without a SubjectKeyId: identify it the same way.
		if aki, err = SubjectKeyID(root.PublicKey); err != nil {
			return nil, err
		}
	}
	nc := p.NameConstraints
	return &x509.Certificate{
		SerialNumber:          serial,
		Subject:               p.Subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            p.MaxPathLen,
		MaxPathLenZero:        p.MaxPathLen == 0,
		SubjectKeyId:          ski,
		AuthorityKeyId:        aki,

		// crypto/x509 writes the extension only when a list is non-empty,
		// and then marks it critical with this flag.
		PermittedDNSDomainsCritical: !nc.Empty(),
		PermittedURIDomains:         slices.Clone(nc.PermittedURIDomains),
		ExcludedURIDomains:          slices.Clone(nc.ExcludedURIDomains),
		PermittedDNSDomains:         slices.Clone(nc.PermittedDNSDomains),
		ExcludedDNSDomains:          slices.Clone(nc.ExcludedDNSDomains),
	}, nil
}

// Issue builds the intermediate for pub from p, signs it with rootSigner
// (the root's key) using sigAlg, parses it back and checks its signature
// against root. sigAlg may be x509.UnknownSignatureAlgorithm to let
// crypto/x509 choose from the signer's key.
func Issue(p Profile, pub crypto.PublicKey, root *x509.Certificate, rootSigner crypto.Signer, sigAlg x509.SignatureAlgorithm, now time.Time) (*x509.Certificate, error) {
	tmpl, err := Template(p, pub, root, now)
	if err != nil {
		return nil, err
	}
	tmpl.SignatureAlgorithm = sigAlg
	der, err := x509.CreateCertificate(rand.Reader, tmpl, root, pub, rootSigner)
	if err != nil {
		return nil, fmt.Errorf("sign the intermediate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse the new intermediate: %w", err)
	}
	if err := cert.CheckSignatureFrom(root); err != nil {
		return nil, fmt.Errorf("the new intermediate does not verify against the root: %w", err)
	}
	return cert, nil
}

// SerialNumber returns a random positive serial number of at most 128 bits.
func SerialNumber(r io.Reader) (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	for {
		n, err := rand.Int(r, limit)
		if err != nil {
			return nil, fmt.Errorf("serial number: %w", err)
		}
		if n.Sign() > 0 {
			return n, nil
		}
	}
}

// SubjectKeyID is the RFC 5280 (section 4.2.1.2) method 1 key identifier:
// the SHA-1 of the subjectPublicKey BIT STRING.
func SubjectKeyID(pub crypto.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("marshal public key: %w", err)
	}
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(der, &spki); err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	sum := sha1.Sum(spki.PublicKey.Bytes)
	return sum[:], nil
}

// The extensions Check looks at the criticality of.
var (
	oidBasicConstraints = asn1.ObjectIdentifier{2, 5, 29, 19}
	oidKeyUsage         = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidNameConstraints  = asn1.ObjectIdentifier{2, 5, 29, 30}
)

// Check reports whether cert is what Issue makes from p: the subject, the CA
// basic constraints and path length, the key usage and the name constraints
// equal the profile, with the criticality Issue gives them, the key is of the
// profile's type, and cert is valid until at least now + Validity - slack.
// It does not check the signature; see the secretformat package for that.
func Check(cert *x509.Certificate, p Profile, now time.Time, slack time.Duration) error {
	checks := []func(*x509.Certificate, Profile) error{
		checkSubject,
		checkKeyType,
		checkBasicConstraints,
		checkKeyUsage,
		checkNameConstraints,
	}
	for _, c := range checks {
		if err := c(cert, p); err != nil {
			return err
		}
	}
	// Certificate times have a precision of one second.
	if earliest := now.Add(p.Validity - slack).Truncate(time.Second); cert.NotAfter.Before(earliest) {
		return fmt.Errorf("not after %s is before %s (validity %s)",
			cert.NotAfter.UTC().Format(time.RFC3339), earliest.UTC().Format(time.RFC3339), p.Validity)
	}
	return nil
}

func checkSubject(cert *x509.Certificate, p Profile) error {
	want, err := asn1.Marshal(p.Subject.ToRDNSequence())
	if err != nil {
		return fmt.Errorf("marshal subject: %w", err)
	}
	if !bytes.Equal(cert.RawSubject, want) {
		return fmt.Errorf("subject %q, want %q", cert.Subject, p.Subject)
	}
	return nil
}

func checkKeyType(cert *x509.Certificate, p Profile) error {
	kt, err := KeyTypeOf(cert.PublicKey)
	if err != nil {
		return err
	}
	if kt != p.KeyType {
		return fmt.Errorf("key type %s, want %s", kt, p.KeyType)
	}
	return nil
}

func checkBasicConstraints(cert *x509.Certificate, p Profile) error {
	if !cert.BasicConstraintsValid || !cert.IsCA {
		return errors.New("not a CA (basic constraints CA:TRUE missing)")
	}
	if !critical(cert, oidBasicConstraints) {
		return errors.New("basic constraints are not critical")
	}
	if cert.MaxPathLen != p.MaxPathLen || (p.MaxPathLen == 0 && !cert.MaxPathLenZero) {
		return fmt.Errorf("path length %d (zero: %t), want %d", cert.MaxPathLen, cert.MaxPathLenZero, p.MaxPathLen)
	}
	return nil
}

func checkKeyUsage(cert *x509.Certificate, _ Profile) error {
	if want := x509.KeyUsageCertSign | x509.KeyUsageCRLSign; cert.KeyUsage != want {
		return fmt.Errorf("key usage %#x, want certSign|crlSign (%#x)", cert.KeyUsage, want)
	}
	if !critical(cert, oidKeyUsage) {
		return errors.New("key usage is not critical")
	}
	if len(cert.ExtKeyUsage) != 0 || len(cert.UnknownExtKeyUsage) != 0 {
		return errors.New("unexpected extended key usage")
	}
	return nil
}

func checkNameConstraints(cert *x509.Certificate, p Profile) error {
	nc := p.NameConstraints
	got := NameConstraints{
		PermittedURIDomains: cert.PermittedURIDomains,
		ExcludedURIDomains:  cert.ExcludedURIDomains,
		PermittedDNSDomains: cert.PermittedDNSDomains,
		ExcludedDNSDomains:  cert.ExcludedDNSDomains,
	}
	if !slices.Equal(got.PermittedURIDomains, nc.PermittedURIDomains) ||
		!slices.Equal(got.ExcludedURIDomains, nc.ExcludedURIDomains) ||
		!slices.Equal(got.PermittedDNSDomains, nc.PermittedDNSDomains) ||
		!slices.Equal(got.ExcludedDNSDomains, nc.ExcludedDNSDomains) {
		return fmt.Errorf("name constraints %+v, want %+v", got, nc)
	}
	if len(cert.PermittedIPRanges) != 0 || len(cert.ExcludedIPRanges) != 0 ||
		len(cert.PermittedEmailAddresses) != 0 || len(cert.ExcludedEmailAddresses) != 0 {
		return errors.New("unexpected IP or email name constraints")
	}
	if !nc.Empty() && !critical(cert, oidNameConstraints) {
		return errors.New("name constraints are not critical")
	}
	return nil
}

// critical reports whether cert has the extension oid, marked critical.
func critical(cert *x509.Certificate, oid asn1.ObjectIdentifier) bool {
	for _, e := range cert.Extensions {
		if e.Id.Equal(oid) {
			return e.Critical
		}
	}
	return false
}
