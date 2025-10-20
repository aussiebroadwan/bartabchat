package cryptox_test

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/aussiebroadwan/bartab/pkg/cryptox"
	"github.com/stretchr/testify/require"
)

func TestGenerateEd25519Key(t *testing.T) {
	pemBytes, err := cryptox.GenerateEd25519Key()
	require.NoError(t, err)
	require.NotEmpty(t, pemBytes)

	// Verify it's valid PEM
	block, _ := pem.Decode(pemBytes)
	require.NotNil(t, block)
	require.Equal(t, "PRIVATE KEY", block.Type)

	// Verify it's a valid Ed25519 key in PKCS8 format
	keyInterface, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	require.NoError(t, err)
	require.NotNil(t, keyInterface)

	key, ok := keyInterface.(ed25519.PrivateKey)
	require.True(t, ok)
	require.Equal(t, ed25519.PrivateKeySize, len(key))
}
