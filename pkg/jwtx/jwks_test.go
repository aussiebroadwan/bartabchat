package jwtx

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestJWK_PEM_RSA(t *testing.T) {
	// Generate an RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create a JWK from the public key
	jwk := NewRSAJWK("test-key-id", "sig", "RS256", &privateKey.PublicKey)

	// Convert to PEM
	pemStr, err := jwk.PEM()
	require.NoError(t, err)
	require.NotEmpty(t, pemStr)

	// Verify the PEM format
	require.True(t, strings.HasPrefix(pemStr, "-----BEGIN PUBLIC KEY-----"))
	require.True(t, strings.HasSuffix(strings.TrimSpace(pemStr), "-----END PUBLIC KEY-----"))

	// Parse the PEM back to verify it's valid
	block, _ := pem.Decode([]byte(pemStr))
	require.NotNil(t, block, "PEM block should be valid")
	require.Equal(t, "PUBLIC KEY", block.Type)

	// Parse the public key
	parsedKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	require.NoError(t, err)

	// Verify it's an RSA public key
	rsaPubKey, ok := parsedKey.(*rsa.PublicKey)
	require.True(t, ok, "Parsed key should be an RSA public key")

	// Verify the key matches
	require.Equal(t, privateKey.PublicKey.N, rsaPubKey.N)
	require.Equal(t, privateKey.PublicKey.E, rsaPubKey.E)
}

func TestJWK_PEM_Ed25519(t *testing.T) {
	// Generate an Ed25519 key pair
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	// Create a JWK from the public key
	jwk := NewEd25519JWK("test-key-id", "sig", "EdDSA", publicKey)

	// Convert to PEM
	pemStr, err := jwk.PEM()
	require.NoError(t, err)
	require.NotEmpty(t, pemStr)

	// Verify the PEM format
	require.True(t, strings.HasPrefix(pemStr, "-----BEGIN PUBLIC KEY-----"))
	require.True(t, strings.HasSuffix(strings.TrimSpace(pemStr), "-----END PUBLIC KEY-----"))

	// Parse the PEM back to verify it's valid
	block, _ := pem.Decode([]byte(pemStr))
	require.NotNil(t, block, "PEM block should be valid")
	require.Equal(t, "PUBLIC KEY", block.Type)

	// Parse the public key
	parsedKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	require.NoError(t, err)

	// Verify it's an Ed25519 public key
	ed25519PubKey, ok := parsedKey.(ed25519.PublicKey)
	require.True(t, ok, "Parsed key should be an Ed25519 public key")

	// Verify the key matches
	require.Equal(t, publicKey, ed25519PubKey)
}

func TestJWK_PEM_ES256(t *testing.T) {
	// Generate an ECDSA P-256 key pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Create a JWK from the public key
	jwk := NewES256JWK("test-key-id", "sig", "ES256", &privateKey.PublicKey)

	// Convert to PEM
	pemStr, err := jwk.PEM()
	require.NoError(t, err)
	require.NotEmpty(t, pemStr)

	// Verify the PEM format
	require.True(t, strings.HasPrefix(pemStr, "-----BEGIN PUBLIC KEY-----"))
	require.True(t, strings.HasSuffix(strings.TrimSpace(pemStr), "-----END PUBLIC KEY-----"))

	// Parse the PEM back to verify it's valid
	block, _ := pem.Decode([]byte(pemStr))
	require.NotNil(t, block, "PEM block should be valid")
	require.Equal(t, "PUBLIC KEY", block.Type)

	// Parse the public key
	parsedKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	require.NoError(t, err)

	// Verify it's an ECDSA public key
	ecdsaPubKey, ok := parsedKey.(*ecdsa.PublicKey)
	require.True(t, ok, "Parsed key should be an ECDSA public key")

	// Verify the key matches
	require.Equal(t, privateKey.PublicKey.X, ecdsaPubKey.X)
	require.Equal(t, privateKey.PublicKey.Y, ecdsaPubKey.Y)
	require.Equal(t, privateKey.PublicKey.Curve, ecdsaPubKey.Curve)
}

func TestJWK_PEM_UnsupportedKeyType(t *testing.T) {
	jwk := JWK{
		Kty: "UNSUPPORTED",
		Kid: "test-key",
	}

	_, err := jwk.PEM()
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported kty")
}

func TestJWK_PEM_InvalidBase64(t *testing.T) {
	jwk := JWK{
		Kty: "RSA",
		Kid: "test-key",
		N:   "!!!invalid-base64!!!",
		E:   "AQAB",
	}

	_, err := jwk.PEM()
	require.Error(t, err)
}
