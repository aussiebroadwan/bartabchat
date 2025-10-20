package jwtx

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
)

// JWK represents a public key in JSON Web Key format (RFC 7517).
// It's algorithm-neutral, so we can support RSA, Ed25519, and ECDSA
// whenever we get around to it.
type JWK struct {
	Kty string `json:"kty"`           // key type: "RSA"; Later: "OKP", "EC"
	Use string `json:"use,omitempty"` // what we use it for: "sig", "enc"
	Alg string `json:"alg,omitempty"` // algorithm: "RS256"; Later: "EdDSA", etc.
	Kid string `json:"kid,omitempty"` // key ID

	// RSA stuff
	N string `json:"n,omitempty"` // modulus (base64url)
	E string `json:"e,omitempty"` // exponent (base64url)

	// Ed25519 / OKP fields and ECDSA / EC fields
	Crv string `json:"crv,omitempty"` // curve: "Ed25519", "P-256", "P-384", "P-521"
	X   string `json:"x,omitempty"`   // base64url encoded public key or x-coordinate
	Y   string `json:"y,omitempty"`   // base64url encoded y-coordinate (ECDSA only)
}

// JWKS is a JSON Web Key Set (RFC 7517).
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// NewRSAJWK builds a JWK for an RSA public key.
func NewRSAJWK(kid, use, alg string, pub *rsa.PublicKey) JWK {
	return JWK{
		Kty: "RSA",
		Use: use,
		Alg: alg,
		Kid: kid,
		N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
}

// NewEd25519JWK builds a JWK for an Ed25519 public key.
// Ed25519 keys use the "OKP" (Octet Key Pair) key type.
func NewEd25519JWK(kid, use, alg string, pub ed25519.PublicKey) JWK {
	return JWK{
		Kty: "OKP",
		Use: use,
		Alg: alg,
		Kid: kid,
		Crv: "Ed25519",
		X:   base64.RawURLEncoding.EncodeToString(pub),
	}
}

// NewES256JWK builds a JWK for an ECDSA P-256 public key.
// ES256 keys use the "EC" (Elliptic Curve) key type with the P-256 curve.
func NewES256JWK(kid, use, alg string, pub *ecdsa.PublicKey) JWK {
	// P-256 curve points are 32 bytes each (256 bits)
	// Pad to 32 bytes to ensure consistent encoding
	xBytes := pub.X.Bytes()
	yBytes := pub.Y.Bytes()

	// Ensure the coordinates are exactly 32 bytes (P-256 field size)
	x := make([]byte, 32)
	y := make([]byte, 32)
	copy(x[32-len(xBytes):], xBytes)
	copy(y[32-len(yBytes):], yBytes)

	return JWK{
		Kty: "EC",
		Use: use,
		Alg: alg,
		Kid: kid,
		Crv: "P-256",
		X:   base64.RawURLEncoding.EncodeToString(x),
		Y:   base64.RawURLEncoding.EncodeToString(y),
	}
}

// PEM converts the JWK to PEM format for use with tools like jwt.io.
// Returns the PEM-encoded public key as a string, or an error if the conversion fails.
func (j JWK) PEM() (string, error) {
	// Parse the JWK into a crypto public key
	var publicKey any
	var err error

	switch j.Kty {
	case "RSA":
		// Decode RSA modulus and exponent
		nb, err := base64.RawURLEncoding.DecodeString(j.N)
		if err != nil {
			return "", err
		}
		eb, err := base64.RawURLEncoding.DecodeString(j.E)
		if err != nil {
			return "", err
		}
		n := new(big.Int).SetBytes(nb)
		e := new(big.Int).SetBytes(eb).Int64()
		publicKey = &rsa.PublicKey{N: n, E: int(e)}

	case "OKP":
		// Only Ed25519 is supported for now
		if j.Crv != "Ed25519" {
			return "", errors.New("jwtx: unsupported OKP curve " + j.Crv)
		}
		xb, err := base64.RawURLEncoding.DecodeString(j.X)
		if err != nil {
			return "", err
		}
		if len(xb) != ed25519.PublicKeySize {
			return "", errors.New("jwtx: invalid Ed25519 public key size")
		}
		publicKey = ed25519.PublicKey(xb)

	case "EC":
		// Only P-256 is supported for now
		if j.Crv != "P-256" {
			return "", errors.New("jwtx: unsupported EC curve " + j.Crv)
		}
		xb, err := base64.RawURLEncoding.DecodeString(j.X)
		if err != nil {
			return "", err
		}
		yb, err := base64.RawURLEncoding.DecodeString(j.Y)
		if err != nil {
			return "", err
		}
		x := new(big.Int).SetBytes(xb)
		y := new(big.Int).SetBytes(yb)
		publicKey = &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     x,
			Y:     y,
		}

	default:
		return "", errors.New("jwtx: unsupported kty " + j.Kty)
	}

	// Marshal the public key to PKIX format
	derBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", err
	}

	// Encode to PEM format
	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derBytes,
	}

	return string(pem.EncodeToMemory(pemBlock)), nil
}
