package cryptox_test

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/aussiebroadwan/bartab/pkg/cryptox"
	"github.com/stretchr/testify/require"
)

func TestGenerateRSAKey(t *testing.T) {
	pemBytes, err := cryptox.GenerateRSAKey(2048)
	require.NoError(t, err)
	require.NotEmpty(t, pemBytes)

	// Verify it's valid PEM
	block, _ := pem.Decode(pemBytes)
	require.NotNil(t, block)
	require.Equal(t, "RSA PRIVATE KEY", block.Type)

	// Verify it's a valid RSA key
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	require.NoError(t, err)
	require.NotNil(t, key)
	require.Equal(t, 2048, key.N.BitLen())
}

func TestGenerateRSAKeyPKCS8(t *testing.T) {
	pemBytes, err := cryptox.GenerateRSAKeyPKCS8(2048)
	require.NoError(t, err)
	require.NotEmpty(t, pemBytes)

	// Verify it's valid PEM
	block, _ := pem.Decode(pemBytes)
	require.NotNil(t, block)
	require.Equal(t, "PRIVATE KEY", block.Type)

	// Verify it's a valid RSA key in PKCS8 format
	keyInterface, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	require.NoError(t, err)
	require.NotNil(t, keyInterface)

	key, ok := keyInterface.(*rsa.PrivateKey)
	require.True(t, ok)
	require.Equal(t, 2048, key.N.BitLen())
}

func TestGenerateRSAKeyRejectsTooSmall(t *testing.T) {
	_, err := cryptox.GenerateRSAKey(1024)
	require.Error(t, err)
	require.Contains(t, err.Error(), "at least 2048 bits")
}

func TestGenerateRSAKeyPKCS8RejectsTooSmall(t *testing.T) {
	_, err := cryptox.GenerateRSAKeyPKCS8(1024)
	require.Error(t, err)
	require.Contains(t, err.Error(), "at least 2048 bits")
}
