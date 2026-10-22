package intermediate

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
)

// KeyType is the kind of private key generated for a new intermediate.
type KeyType string

// The key types an intermediate can have.
const (
	KeyTypeECP256  KeyType = "ec-p256"
	KeyTypeECP384  KeyType = "ec-p384"
	KeyTypeRSA2048 KeyType = "rsa-2048"
	KeyTypeRSA4096 KeyType = "rsa-4096"
)

// DefaultKeyType is the key type used when the configuration names none.
const DefaultKeyType = KeyTypeECP256

// Valid reports whether k is one of the known key types.
func (k KeyType) Valid() bool {
	switch k {
	case KeyTypeECP256, KeyTypeECP384, KeyTypeRSA2048, KeyTypeRSA4096:
		return true
	}
	return false
}

// GenerateKey creates a new private key of type k from crypto/rand.
func GenerateKey(k KeyType) (crypto.Signer, error) {
	switch k {
	case KeyTypeECP256:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case KeyTypeECP384:
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case KeyTypeRSA2048:
		return rsa.GenerateKey(rand.Reader, 2048)
	case KeyTypeRSA4096:
		return rsa.GenerateKey(rand.Reader, 4096)
	}
	return nil, fmt.Errorf("unknown key type %q", k)
}

// KeyTypeOf returns the key type of a public key, or an error when it is not
// one of the known types.
func KeyTypeOf(pub crypto.PublicKey) (KeyType, error) {
	switch p := pub.(type) {
	case *ecdsa.PublicKey:
		switch p.Curve {
		case elliptic.P256():
			return KeyTypeECP256, nil
		case elliptic.P384():
			return KeyTypeECP384, nil
		}
	case *rsa.PublicKey:
		switch p.N.BitLen() {
		case 2048:
			return KeyTypeRSA2048, nil
		case 4096:
			return KeyTypeRSA4096, nil
		}
	}
	return "", fmt.Errorf("unsupported public key %T", pub)
}
