package jwtx

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"sync"
)

var ErrNoKey = errors.New("jwtx: key not found")

// KeySet holds all public verification keys in memory.
// It's thread-safe, so both auth (for JWKS publishing) and resource services
// (for verification) can use it causing chaos (tm).
type KeySet struct {
	mu  sync.RWMutex
	jks JWKS
	pub map[string]any // kid: *rsa.PublicKey | ed25519.PublicKey | etc.
}

// NewKeySet returns an empty KeySet.
func NewKeySet() *KeySet {
	return &KeySet{
		pub: make(map[string]any),
	}
}

// AddSigner registers a Signer’s public JWK into the KeySet.
func (k *KeySet) AddSigner(s Signer) error {
	return k.AddJWK(s.PublicJWK())
}

// AddJWK adds a JWK to the KeySet and parses it into a usable crypto key.
func (k *KeySet) AddJWK(j JWK) error {
	key, err := parseJWKToKey(j)
	if err != nil {
		return err
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	k.pub[j.Kid] = key
	k.jks.Keys = append(k.jks.Keys, j)
	return nil
}

// Get returns the public key for the given kid.
func (k *KeySet) Get(kid string) (any, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	if pk, ok := k.pub[kid]; ok {
		return pk, nil
	}
	return nil, ErrNoKey
}

// PublicJWKS returns a snapshot of the KeySet's JWKS for HTTP serving.
func (k *KeySet) PublicJWKS() JWKS {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.jks
}

// IsReady returns true if the KeySet has at least one key loaded.
func (k *KeySet) IsReady() bool {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return len(k.pub) > 0
}

// ResetFromJWKS replaces all keys from a JWKS. We use this when fetching
// fresh keys from the auth service.
func (k *KeySet) ResetFromJWKS(jwks JWKS) error {
	newMap := make(map[string]any, len(jwks.Keys))
	for _, j := range jwks.Keys {
		key, err := parseJWKToKey(j)
		if err != nil {
			return err
		}
		newMap[j.Kid] = key
	}

	k.mu.Lock()
	defer k.mu.Unlock()

	// Set the new map
	k.pub = newMap
	k.jks = jwks

	return nil
}

// parseJWKToKey converts a JWK into a crypto.PublicKey.
// Supports RSA, Ed25519 (OKP), and ECDSA (EC) key types.
func parseJWKToKey(j JWK) (any, error) {
	switch j.Kty {
	case "RSA":
		nb, err := base64.RawURLEncoding.DecodeString(j.N)
		if err != nil {
			return nil, err
		}
		eb, err := base64.RawURLEncoding.DecodeString(j.E)
		if err != nil {
			return nil, err
		}
		n := new(big.Int).SetBytes(nb)
		e := new(big.Int).SetBytes(eb).Int64()
		return &rsa.PublicKey{N: n, E: int(e)}, nil

	case "OKP":
		// Only Ed25519 is supported for now
		if j.Crv != "Ed25519" {
			return nil, errors.New("jwtx: unsupported OKP curve " + j.Crv)
		}
		xb, err := base64.RawURLEncoding.DecodeString(j.X)
		if err != nil {
			return nil, err
		}
		if len(xb) != ed25519.PublicKeySize {
			return nil, errors.New("jwtx: invalid Ed25519 public key size")
		}
		return ed25519.PublicKey(xb), nil

	case "EC":
		// Only P-256 is supported for now
		if j.Crv != "P-256" {
			return nil, errors.New("jwtx: unsupported EC curve " + j.Crv)
		}
		xb, err := base64.RawURLEncoding.DecodeString(j.X)
		if err != nil {
			return nil, err
		}
		yb, err := base64.RawURLEncoding.DecodeString(j.Y)
		if err != nil {
			return nil, err
		}
		x := new(big.Int).SetBytes(xb)
		y := new(big.Int).SetBytes(yb)
		return &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     x,
			Y:     y,
		}, nil

	default:
		return nil, errors.New("jwtx: unsupported kty " + j.Kty)
	}
}

// MarshalJSON ensures stable encoding for JWKS output.
func (j JWK) MarshalJSON() ([]byte, error) {
	type alias JWK
	return json.Marshal(alias(j))
}
