// Package kmssigner is a crypto.Signer backed by an asymmetric AWS KMS key:
// it signs digests with KMS Sign (MessageType DIGEST), so the private key
// never leaves KMS.
package kmssigner

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"slices"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// Client is the part of the KMS API the signer uses.
type Client interface {
	GetPublicKey(ctx context.Context, in *kms.GetPublicKeyInput, optFns ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error)
	Sign(ctx context.Context, in *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error)
}

// algorithm is what a KMS signing algorithm means on the crypto/x509 side.
type algorithm struct {
	hash crypto.Hash
	x509 x509.SignatureAlgorithm
	pss  bool
}

var algorithms = map[types.SigningAlgorithmSpec]algorithm{
	types.SigningAlgorithmSpecEcdsaSha256:          {crypto.SHA256, x509.ECDSAWithSHA256, false},
	types.SigningAlgorithmSpecEcdsaSha384:          {crypto.SHA384, x509.ECDSAWithSHA384, false},
	types.SigningAlgorithmSpecEcdsaSha512:          {crypto.SHA512, x509.ECDSAWithSHA512, false},
	types.SigningAlgorithmSpecRsassaPkcs1V15Sha256: {crypto.SHA256, x509.SHA256WithRSA, false},
	types.SigningAlgorithmSpecRsassaPkcs1V15Sha384: {crypto.SHA384, x509.SHA384WithRSA, false},
	types.SigningAlgorithmSpecRsassaPkcs1V15Sha512: {crypto.SHA512, x509.SHA512WithRSA, false},
	types.SigningAlgorithmSpecRsassaPssSha256:      {crypto.SHA256, x509.SHA256WithRSAPSS, true},
	types.SigningAlgorithmSpecRsassaPssSha384:      {crypto.SHA384, x509.SHA384WithRSAPSS, true},
	types.SigningAlgorithmSpecRsassaPssSha512:      {crypto.SHA512, x509.SHA512WithRSAPSS, true},
}

// DefaultAlgorithm is the signing algorithm used for a key spec when the
// configuration names none.
func DefaultAlgorithm(spec types.KeySpec) (types.SigningAlgorithmSpec, error) {
	switch spec {
	case types.KeySpecEccNistP256:
		return types.SigningAlgorithmSpecEcdsaSha256, nil
	case types.KeySpecEccNistP384:
		return types.SigningAlgorithmSpecEcdsaSha384, nil
	case types.KeySpecEccNistP521:
		return types.SigningAlgorithmSpecEcdsaSha512, nil
	case types.KeySpecRsa2048, types.KeySpecRsa3072, types.KeySpecRsa4096:
		return types.SigningAlgorithmSpecRsassaPkcs1V15Sha256, nil
	}
	return "", fmt.Errorf("unsupported KMS key spec %q", spec)
}

// Signer signs with a KMS key. Its Sign calls KMS with
// context.Background(), or with the context given to WithContext.
type Signer struct {
	client    Client
	keyID     string
	public    crypto.PublicKey
	algorithm types.SigningAlgorithmSpec
	params    algorithm
	ctx       context.Context
}

var _ crypto.Signer = (*Signer)(nil)

// New returns a signer for the KMS key keyID. It calls GetPublicKey once and
// refuses the key unless it is a SIGN_VERIFY key whose public key equals
// expected (the configured root certificate's) and that supports the
// signing algorithm: signingAlgorithm, or when it is empty the default for
// the key spec (DefaultAlgorithm).
func New(ctx context.Context, client Client, keyID, signingAlgorithm string, expected crypto.PublicKey) (*Signer, error) {
	out, err := client.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: aws.String(keyID)})
	if err != nil {
		return nil, fmt.Errorf("kms GetPublicKey: %w", err)
	}
	if out.KeyUsage != types.KeyUsageTypeSignVerify {
		return nil, fmt.Errorf("the KMS key's usage is %q, want %q", out.KeyUsage, types.KeyUsageTypeSignVerify)
	}
	pub, err := x509.ParsePKIXPublicKey(out.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("parse the KMS public key: %w", err)
	}
	want, ok := expected.(interface{ Equal(crypto.PublicKey) bool })
	if !ok || !want.Equal(pub) {
		return nil, errors.New("the KMS key's public key does not match the root certificate's")
	}
	alg, err := chooseAlgorithm(out, signingAlgorithm)
	if err != nil {
		return nil, err
	}
	// Sign with the key ARN GetPublicKey resolved keyID to, so that an
	// alias is resolved once, at start, and cannot move to another key in
	// between.
	resolved := aws.ToString(out.KeyId)
	if resolved == "" {
		resolved = keyID
	}
	return &Signer{
		client:    client,
		keyID:     resolved,
		public:    pub,
		algorithm: alg,
		params:    algorithms[alg],
		ctx:       context.Background(),
	}, nil
}

func chooseAlgorithm(out *kms.GetPublicKeyOutput, configured string) (types.SigningAlgorithmSpec, error) {
	alg := types.SigningAlgorithmSpec(configured)
	if configured == "" {
		var err error
		if alg, err = DefaultAlgorithm(out.KeySpec); err != nil {
			return "", err
		}
	}
	if _, ok := algorithms[alg]; !ok {
		return "", fmt.Errorf("unsupported signing algorithm %q", alg)
	}
	if !slices.Contains(out.SigningAlgorithms, alg) {
		return "", fmt.Errorf("the KMS key (%s) does not support signing algorithm %q", out.KeySpec, alg)
	}
	return alg, nil
}

// WithContext returns a copy of s whose Sign calls KMS with ctx.
func (s *Signer) WithContext(ctx context.Context) *Signer {
	c := *s
	c.ctx = ctx
	return &c
}

// KeyID is the key ARN the signer signs with, as GetPublicKey returned it.
func (s *Signer) KeyID() string { return s.keyID }

// Public returns the KMS key's public key.
func (s *Signer) Public() crypto.PublicKey { return s.public }

// Algorithm is the KMS signing algorithm the signer uses.
func (s *Signer) Algorithm() types.SigningAlgorithmSpec { return s.algorithm }

// SignatureAlgorithm is the crypto/x509 signature algorithm matching
// Algorithm, for a certificate template.
func (s *Signer) SignatureAlgorithm() x509.SignatureAlgorithm { return s.params.x509 }

// Sign signs digest, which must be the hash the signing algorithm uses, with
// KMS. rand is unused: KMS supplies its own randomness.
func (s *Signer) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts == nil || opts.HashFunc() != s.params.hash {
		return nil, fmt.Errorf("kmssigner: %s needs a %s digest", s.algorithm, s.params.hash)
	}
	if len(digest) != s.params.hash.Size() {
		return nil, fmt.Errorf("kmssigner: digest is %d bytes, want %d", len(digest), s.params.hash.Size())
	}
	pss, isPSS := opts.(*rsa.PSSOptions)
	if isPSS != s.params.pss {
		return nil, fmt.Errorf("kmssigner: %s and the requested padding disagree", s.algorithm)
	}
	if isPSS && pss.SaltLength != rsa.PSSSaltLengthEqualsHash && pss.SaltLength != s.params.hash.Size() {
		return nil, errors.New("kmssigner: KMS PSS signatures use a salt as long as the hash")
	}
	out, err := s.client.Sign(s.ctx, &kms.SignInput{
		KeyId:            aws.String(s.keyID),
		Message:          digest,
		MessageType:      types.MessageTypeDigest,
		SigningAlgorithm: s.algorithm,
	})
	if err != nil {
		return nil, fmt.Errorf("kms Sign: %w", err)
	}
	return out.Signature, nil
}
