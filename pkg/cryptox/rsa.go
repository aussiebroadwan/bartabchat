package cryptox

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// GenerateRSAKey generates a new RSA private key with the specified bit size.
// Common bit sizes are 2048, 3072, or 4096 bits.
// Returns the private key in PEM format (PKCS1).
func GenerateRSAKey(bits int) ([]byte, error) {
	if bits < 2048 {
		return nil, fmt.Errorf("cryptox: RSA key size must be at least 2048 bits")
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, fmt.Errorf("cryptox: failed to generate RSA key: %w", err)
	}

	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}

	return pem.EncodeToMemory(privateKeyPEM), nil
}

// GenerateRSAKeyPKCS8 generates a new RSA private key in PKCS8 format.
// PKCS8 is more modern and supports multiple key types.
func GenerateRSAKeyPKCS8(bits int) ([]byte, error) {
	if bits < 2048 {
		return nil, fmt.Errorf("cryptox: RSA key size must be at least 2048 bits")
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, fmt.Errorf("cryptox: failed to generate RSA key: %w", err)
	}

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
