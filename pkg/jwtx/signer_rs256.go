package jwtx

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

// RS256Signer implements the Signer interface using RSA SHA-256.
type RS256Signer struct {
	kid string
	key *rsa.PrivateKey
	pub *rsa.PublicKey
	alg string
}

// newRS256Signer loads an RSA private key from PEM bytes. Handles both
// PKCS1 and PKCS8 because otherwise we will be chasing a bug for longer
// that we would be willing to admit.
func newRS256Signer(kid string, pemKey []byte) (*RS256Signer, error) {
	block, _ := pem.Decode(pemKey)
	if block == nil {
		return nil, errors.New("jwtx: invalid PEM for RSA key")
	}

	var key *rsa.PrivateKey
	var err error

	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		priv, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err2 != nil {
			return nil, fmt.Errorf("jwtx: parse PKCS8: %w", err2)
		}
		rk, ok := priv.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("jwtx: not RSA private key")
		}
		key = rk
	default:
		return nil, fmt.Errorf("jwtx: unsupported PEM type %q", block.Type)
	}

	if err != nil {
		return nil, fmt.Errorf("jwtx: parse RSA key: %w", err)
	}

	return &RS256Signer{
		kid: kid,
		key: key,
		pub: &key.PublicKey,
		alg: jwt.SigningMethodRS256.Alg(),
	}, nil
}

func (s *RS256Signer) Alg() string { return s.alg }
func (s *RS256Signer) KID() string { return s.kid }

// Sign takes your claims and turns them into a signed JWT string.
func (s *RS256Signer) Sign(claims Claims) (string, error) {
	t := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	t.Header["kid"] = s.kid
	return t.SignedString(s.key)
}

// PublicJWK returns a JWK for inclusion in a JWKS. This is what you'll
// publish so others can verify your tokens.
func (s *RS256Signer) PublicJWK() JWK {
	return NewRSAJWK(s.kid, "sig", s.alg, s.pub)
}

// Validate does a quick sanity check to make sure we actually have keys.
func (s *RS256Signer) Validate() error {
	if s.key == nil || s.pub == nil {
		return errors.New("jwtx: nil RSA key")
	}
	return nil
}

// RotateKey creates a new signer with a different RSA keypair but same KID.
// Useful when you need to rotate keys but keep everything else the same.
func (s *RS256Signer) RotateKey(newPEM []byte) (*RS256Signer, error) {
	return newRS256Signer(s.kid, newPEM)
}
