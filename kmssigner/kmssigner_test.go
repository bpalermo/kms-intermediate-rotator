package kmssigner_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/bpalermo/kms-intermediate-rotator/internal/kmsfake"
	"github.com/bpalermo/kms-intermediate-rotator/internal/testca"
	"github.com/bpalermo/kms-intermediate-rotator/kmssigner"
)

const keyID = "alias/example-root"

func digest(h crypto.Hash, msg []byte) []byte {
	switch h {
	case crypto.SHA256:
		d := sha256.Sum256(msg)
		return d[:]
	case crypto.SHA384:
		d := sha512.Sum384(msg)
		return d[:]
	}
	panic("unexpected hash")
}

func TestSignDigest(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		key     crypto.Signer
		alg     string
		wantAlg types.SigningAlgorithmSpec
		hash    crypto.Hash
		x509Alg x509.SignatureAlgorithm
	}{
		{"p384 default", testca.NewKey(t, elliptic.P384()), "", types.SigningAlgorithmSpecEcdsaSha384, crypto.SHA384, x509.ECDSAWithSHA384},
		{"p256 default", testca.NewKey(t, elliptic.P256()), "", types.SigningAlgorithmSpecEcdsaSha256, crypto.SHA256, x509.ECDSAWithSHA256},
		{"p256 configured", testca.NewKey(t, elliptic.P256()), "ECDSA_SHA_256", types.SigningAlgorithmSpecEcdsaSha256, crypto.SHA256, x509.ECDSAWithSHA256},
		{"rsa default", rsaKey, "", types.SigningAlgorithmSpecRsassaPkcs1V15Sha256, crypto.SHA256, x509.SHA256WithRSA},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := kmsfake.New(keyID, tc.key)
			s, err := kmssigner.New(context.Background(), fake, keyID, tc.alg, tc.key.Public())
			if err != nil {
				t.Fatal(err)
			}
			if s.Algorithm() != tc.wantAlg || s.SignatureAlgorithm() != tc.x509Alg {
				t.Fatalf("algorithm %s/%s, want %s/%s", s.Algorithm(), s.SignatureAlgorithm(), tc.wantAlg, tc.x509Alg)
			}
			d := digest(tc.hash, []byte("message"))
			sig, err := s.Sign(rand.Reader, d, tc.hash)
			if err != nil {
				t.Fatal(err)
			}
			// The alias is resolved once, by GetPublicKey: Sign names the key ARN.
			if in := fake.LastSign(); in.MessageType != types.MessageTypeDigest || in.SigningAlgorithm != tc.wantAlg ||
				aws.ToString(in.KeyId) != kmsfake.KeyARN || s.KeyID() != kmsfake.KeyARN {
				t.Fatalf("KMS Sign called with %s/%s on %s", in.MessageType, in.SigningAlgorithm, aws.ToString(in.KeyId))
			}
			if !verify(t, s.Public(), tc.hash, d, sig) {
				t.Fatal("signature does not verify")
			}
		})
	}
}

func verify(t *testing.T, pub crypto.PublicKey, h crypto.Hash, d, sig []byte) bool {
	t.Helper()
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		return ecdsa.VerifyASN1(k, d, sig)
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(k, h, d, sig) == nil
	}
	t.Fatalf("unexpected key %T", pub)
	return false
}

func TestNewRefuses(t *testing.T) {
	key := testca.NewKey(t, elliptic.P384())
	other := testca.NewKey(t, elliptic.P384())
	for _, tc := range []struct {
		name     string
		keyID    string
		alg      string
		expected crypto.PublicKey
	}{
		{"public key mismatch", keyID, "", other.Public()},
		{"unknown key", "alias/other", "", key.Public()},
		{"algorithm not supported by the key", keyID, "ECDSA_SHA_256", key.Public()},
		{"unknown algorithm", keyID, "HMAC_SHA_256", key.Public()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := kmssigner.New(context.Background(), kmsfake.New(keyID, key), tc.keyID, tc.alg, tc.expected); err == nil {
				t.Fatal("New succeeded, want an error")
			}
		})
	}
}

func TestSignRejectsWrongDigest(t *testing.T) {
	key := testca.NewKey(t, elliptic.P384())
	fake := kmsfake.New(keyID, key)
	s, err := kmssigner.New(context.Background(), fake, keyID, "", key.Public())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		digest []byte
		opts   crypto.SignerOpts
	}{
		{"wrong hash", digest(crypto.SHA256, nil), crypto.SHA256},
		{"wrong length", make([]byte, 20), crypto.SHA384},
		{"pss on ecdsa", digest(crypto.SHA384, nil), &rsa.PSSOptions{Hash: crypto.SHA384}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := s.Sign(rand.Reader, tc.digest, tc.opts); err == nil {
				t.Fatal("Sign succeeded, want an error")
			}
		})
	}
	if fake.Signs() != 0 {
		t.Fatalf("KMS Sign was called %d times", fake.Signs())
	}
}

// The signer is what x509.CreateCertificate needs: a certificate it signs
// verifies against the root.
func TestSignCertificate(t *testing.T) {
	key := testca.NewKey(t, elliptic.P384())
	root := testca.NewRoot(t, key, time.Hour)
	s, err := kmssigner.New(context.Background(), kmsfake.New(keyID, key), keyID, "", root.Cert.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := *root.Cert
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, root.Cert, root.Cert.PublicKey, s)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if err := cert.CheckSignatureFrom(root.Cert); err != nil {
		t.Fatal(err)
	}
}
