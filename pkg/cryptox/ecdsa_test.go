package cryptox_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/aussiebroadwan/bartab/pkg/cryptox"
	"github.com/stretchr/testify/require"
)

func TestGenerateES256Key(t *testing.T) {
	pemBytes, err := cryptox.GenerateES256Key()
	require.NoError(t, err)
	require.NotEmpty(t, pemBytes)

	// Verify it's valid PEM
	block, _ := pem.Decode(pemBytes)
	require.NotNil(t, block)
	require.Equal(t, "PRIVATE KEY", block.Type)

	// Verify it's a valid ECDSA key in PKCS8 format
	keyInterface, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	require.NoError(t, err)
	require.NotNil(t, keyInterface)

	key, ok := keyInterface.(*ecdsa.PrivateKey)
	require.True(t, ok)
	require.NotNil(t, key)

	// Verify it's using the P-256 curve
	require.Equal(t, elliptic.P256(), key.Curve)
}
