package jwtx

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

// ES256Signer implements the Signer interface using ECDSA P-256 with SHA-256.
type ES256Signer struct {
	kid string
	key *ecdsa.PrivateKey
	pub *ecdsa.PublicKey
	alg string
}

// newES256Signer loads an ECDSA private key from PEM bytes.
// ES256 keys must be in PKCS8 format.
func newES256Signer(kid string, pemKey []byte) (*ES256Signer, error) {
	block, _ := pem.Decode(pemKey)
	if block == nil {
		return nil, errors.New("jwtx: invalid PEM for ES256 key")
	}

	if block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("jwtx: expected PRIVATE KEY, got %q (ES256 requires PKCS8)", block.Type)
	}

	// Parse PKCS8 private key
	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("jwtx: parse PKCS8: %w", err)
	}

	// Make sure it's actually an ECDSA key
	key, ok := priv.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("jwtx: not ECDSA private key")
	}

	// Extract public key from private key
	pub := &key.PublicKey

	return &ES256Signer{
		kid: kid,
		key: key,
		pub: pub,
		alg: jwt.SigningMethodES256.Alg(),
	}, nil
}

func (s *ES256Signer) Alg() string { return s.alg }
func (s *ES256Signer) KID() string { return s.kid }

// Sign takes your claims and turns them into a signed JWT string.
func (s *ES256Signer) Sign(claims Claims) (string, error) {
	t := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	t.Header["kid"] = s.kid
	return t.SignedString(s.key)
}

// PublicJWK returns a JWK for inclusion in a JWKS. This is what you'll
// publish so others can verify your tokens.
func (s *ES256Signer) PublicJWK() JWK {
	return NewES256JWK(s.kid, "sig", s.alg, s.pub)
}

// Validate does a quick sanity check to make sure we actually have keys.
func (s *ES256Signer) Validate() error {
	if s.key == nil || s.pub == nil {
		return errors.New("jwtx: nil ECDSA key")
	}
	// Verify we're using the P-256 curve
	if s.key.Curve.Params().Name != "P-256" {
		return fmt.Errorf("jwtx: expected P-256 curve, got %s", s.key.Curve.Params().Name)
	}
	return nil
}

// RotateKey creates a new signer with a different ECDSA keypair but same KID.
// Useful when you need to rotate keys but keep everything else the same.
func (s *ES256Signer) RotateKey(newPEM []byte) (*ES256Signer, error) {
	return newES256Signer(s.kid, newPEM)
}
