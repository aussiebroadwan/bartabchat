package cryptox

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// GenerateES256Key generates a new ECDSA P-256 private key.
// ES256 uses the P-256 curve (also known as secp256r1 or prime256v1).
// Returns the private key in PEM format (PKCS8).
func GenerateES256Key() ([]byte, error) {
	// Generate ECDSA key with P-256 curve
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("cryptox: failed to generate ECDSA key: %w", err)
	}

	// Marshal to PKCS8 format
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
