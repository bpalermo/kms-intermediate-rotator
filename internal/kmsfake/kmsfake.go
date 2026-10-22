// Package kmsfake is an in-process stand-in for the two KMS operations the
// rotator uses, GetPublicKey and Sign, backed by a real private key. It is
// for tests only: no network, no AWS.
package kmsfake

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// KMS holds one key, known by KeyID (an alias, say) and by KeyARN.
type KMS struct {
	KeyID  string
	KeyARN string
	Key    crypto.Signer

	mu    sync.Mutex
	signs int
	last  *kms.SignInput
}

// KeyARN is the ARN the fake gives its key.
const KeyARN = "arn:aws:kms:us-east-1:111122223333:key/00000000-0000-0000-0000-000000000000"

// New returns a fake holding key under keyID and KeyARN.
func New(keyID string, key crypto.Signer) *KMS {
	return &KMS{KeyID: keyID, KeyARN: KeyARN, Key: key}
}

// Signs is how many successful Sign calls the fake has answered.
func (f *KMS) Signs() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.signs
}

// LastSign is the input of the last successful Sign call.
func (f *KMS) LastSign() *kms.SignInput {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.last
}

func (f *KMS) spec() (types.KeySpec, []types.SigningAlgorithmSpec, error) {
	switch k := f.Key.Public().(type) {
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256():
			return types.KeySpecEccNistP256, []types.SigningAlgorithmSpec{types.SigningAlgorithmSpecEcdsaSha256}, nil
		case elliptic.P384():
			return types.KeySpecEccNistP384, []types.SigningAlgorithmSpec{types.SigningAlgorithmSpecEcdsaSha384}, nil
		}
	case *rsa.PublicKey:
		spec := types.KeySpec(fmt.Sprintf("RSA_%d", k.N.BitLen()))
		return spec, []types.SigningAlgorithmSpec{
			types.SigningAlgorithmSpecRsassaPkcs1V15Sha256,
			types.SigningAlgorithmSpecRsassaPkcs1V15Sha384,
			types.SigningAlgorithmSpecRsassaPkcs1V15Sha512,
			types.SigningAlgorithmSpecRsassaPssSha256,
			types.SigningAlgorithmSpecRsassaPssSha384,
			types.SigningAlgorithmSpecRsassaPssSha512,
		}, nil
	}
	return "", nil, fmt.Errorf("kmsfake: unsupported key %T", f.Key)
}

func (f *KMS) checkKey(id *string) error {
	if s := aws.ToString(id); s != f.KeyID && s != f.KeyARN {
		return &types.NotFoundException{Message: aws.String("kmsfake: no key " + aws.ToString(id))}
	}
	return nil
}

// GetPublicKey answers like KMS for an asymmetric SIGN_VERIFY key.
func (f *KMS) GetPublicKey(_ context.Context, in *kms.GetPublicKeyInput, _ ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	if err := f.checkKey(in.KeyId); err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKIXPublicKey(f.Key.Public())
	if err != nil {
		return nil, err
	}
	spec, algs, err := f.spec()
	if err != nil {
		return nil, err
	}
	return &kms.GetPublicKeyOutput{
		KeyId:             aws.String(f.KeyARN),
		KeySpec:           spec,
		KeyUsage:          types.KeyUsageTypeSignVerify,
		PublicKey:         der,
		SigningAlgorithms: algs,
	}, nil
}

var hashes = map[types.SigningAlgorithmSpec]crypto.Hash{
	types.SigningAlgorithmSpecEcdsaSha256:          crypto.SHA256,
	types.SigningAlgorithmSpecEcdsaSha384:          crypto.SHA384,
	types.SigningAlgorithmSpecRsassaPkcs1V15Sha256: crypto.SHA256,
	types.SigningAlgorithmSpecRsassaPkcs1V15Sha384: crypto.SHA384,
	types.SigningAlgorithmSpecRsassaPkcs1V15Sha512: crypto.SHA512,
	types.SigningAlgorithmSpecRsassaPssSha256:      crypto.SHA256,
	types.SigningAlgorithmSpecRsassaPssSha384:      crypto.SHA384,
	types.SigningAlgorithmSpecRsassaPssSha512:      crypto.SHA512,
}

// Sign signs a digest (MessageType DIGEST only, as the rotator sends) with
// the algorithm asked for, which the key must support.
func (f *KMS) Sign(_ context.Context, in *kms.SignInput, _ ...func(*kms.Options)) (*kms.SignOutput, error) {
	if err := f.checkKey(in.KeyId); err != nil {
		return nil, err
	}
	if in.MessageType != types.MessageTypeDigest {
		return nil, fmt.Errorf("kmsfake: MessageType %q, want DIGEST", in.MessageType)
	}
	_, algs, err := f.spec()
	if err != nil {
		return nil, err
	}
	if !slices.Contains(algs, in.SigningAlgorithm) {
		return nil, &types.InvalidKeyUsageException{Message: aws.String("kmsfake: unsupported algorithm " + string(in.SigningAlgorithm))}
	}
	h := hashes[in.SigningAlgorithm]
	if len(in.Message) != h.Size() {
		return nil, errors.New("kmsfake: digest length does not match the algorithm")
	}
	var opts crypto.SignerOpts = h
	if slices.Contains([]types.SigningAlgorithmSpec{
		types.SigningAlgorithmSpecRsassaPssSha256,
		types.SigningAlgorithmSpecRsassaPssSha384,
		types.SigningAlgorithmSpecRsassaPssSha512,
	}, in.SigningAlgorithm) {
		opts = &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: h}
	}
	sig, err := f.Key.Sign(rand.Reader, in.Message, opts)
	if err != nil {
		return nil, err
	}
	f.mu.Lock()
	f.signs++
	f.last = in
	f.mu.Unlock()
	return &kms.SignOutput{KeyId: aws.String(f.KeyARN), Signature: sig, SigningAlgorithm: in.SigningAlgorithm}, nil
}
