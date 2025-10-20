package cryptox

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// GenerateEd25519Key generates a new Ed25519 private key.
// Ed25519 keys are always 256 bits (32 bytes) and don't require a size parameter.
// Returns the private key in PEM format (PKCS8).
func GenerateEd25519Key() ([]byte, error) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("cryptox: failed to generate Ed25519 key: %w", err)
	}

	// Ed25519 keys are always marshaled as PKCS8
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("cryptox: failed to marshal PKCS8 key: %w", err)
	}

	privateKeyPEM := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	}

	return pem.EncodeToMemory(privateKeyPEM), nil
}
