package jwtx

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

// EdDSASigner implements the Signer interface using Ed25519.
type EdDSASigner struct {
	kid string
	key ed25519.PrivateKey
	pub ed25519.PublicKey
	alg string
}

// newEdDSASigner loads an Ed25519 private key from PEM bytes.
// Ed25519 keys must be in PKCS8 format.
func newEdDSASigner(kid string, pemKey []byte) (*EdDSASigner, error) {
	block, _ := pem.Decode(pemKey)
	if block == nil {
		return nil, errors.New("jwtx: invalid PEM for Ed25519 key")
	}

	if block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("jwtx: expected PRIVATE KEY, got %q (Ed25519 requires PKCS8)", block.Type)
	}

	// Parse PKCS8 private key
	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("jwtx: parse PKCS8: %w", err)
	}

	// Make sure it's actually an Ed25519 key
	key, ok := priv.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("jwtx: not Ed25519 private key")
	}

	// Extract public key from private key
	pub := key.Public().(ed25519.PublicKey)

	return &EdDSASigner{
		kid: kid,
		key: key,
		pub: pub,
		alg: jwt.SigningMethodEdDSA.Alg(),
	}, nil
}

func (s *EdDSASigner) Alg() string { return s.alg }
func (s *EdDSASigner) KID() string { return s.kid }

// Sign takes your claims and turns them into a signed JWT string.
func (s *EdDSASigner) Sign(claims Claims) (string, error) {
	t := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	t.Header["kid"] = s.kid
	return t.SignedString(s.key)
}

// PublicJWK returns a JWK for inclusion in a JWKS. This is what you'll
// publish so others can verify your tokens.
func (s *EdDSASigner) PublicJWK() JWK {
	return NewEd25519JWK(s.kid, "sig", s.alg, s.pub)
}

// Validate does a quick sanity check to make sure we actually have keys.
func (s *EdDSASigner) Validate() error {
	if s.key == nil || s.pub == nil {
		return errors.New("jwtx: nil Ed25519 key")
	}
	if len(s.key) != ed25519.PrivateKeySize {
		return errors.New("jwtx: invalid Ed25519 private key size")
	}
	if len(s.pub) != ed25519.PublicKeySize {
		return errors.New("jwtx: invalid Ed25519 public key size")
	}
	return nil
}

// RotateKey creates a new signer with a different Ed25519 keypair but same KID.
// Useful when you need to rotate keys but keep everything else the same.
func (s *EdDSASigner) RotateKey(newPEM []byte) (*EdDSASigner, error) {
	return newEdDSASigner(s.kid, newPEM)
}
