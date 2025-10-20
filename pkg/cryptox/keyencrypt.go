package cryptox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"sync"
)

var (
	masterKeyOnce sync.Once
	masterKey     []byte
	masterKeyPath string = "" // Can be set via SetMasterKeyPath before first use
)

// SetMasterKeyPath configures where to load the master encryption key from.
// This must be called before any encryption/decryption operations.
// If not set, the key will be loaded from AUTH_MASTER_KEY environment variable.
func SetMasterKeyPath(path string) {
	masterKeyPath = path
}

// loadMasterKey loads and derives a 32-byte AES-256 key from either:
// 1. File specified by masterKeyPath (if set)
// 2. AUTH_MASTER_KEY environment variable
// 3. Generates a temporary key for development (NOT for production)
func loadMasterKey() ([]byte, error) {
	var keyMaterial []byte

	// Try loading from file first
	if masterKeyPath != "" {
		data, err := os.ReadFile(masterKeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read master key file: %w", err)
		}
		keyMaterial = data
	} else {
		// Try environment variable
		envKey := os.Getenv("AUTH_MASTER_KEY")
		if envKey != "" {
			keyMaterial = []byte(envKey)
		} else {
			// Development fallback - generate ephemeral key
			// WARNING: This means keys won't survive restart in development
			keyMaterial = make([]byte, 32)
			if _, err := rand.Read(keyMaterial); err != nil {
				return nil, fmt.Errorf("failed to generate ephemeral master key: %w", err)
			}
		}
	}

	// Derive a proper 32-byte key using SHA-256
	hash := sha256.Sum256(keyMaterial)
	return hash[:], nil
}

// getMasterKey returns the loaded master key, loading it on first use.
func getMasterKey() ([]byte, error) {
	var err error
	masterKeyOnce.Do(func() {
		masterKey, err = loadMasterKey()
	})
	if err != nil {
		return nil, err
	}
	return masterKey, nil
}

// EncryptPrivateKey encrypts a PEM-encoded private key using AES-256-GCM.
// The output format is: [12-byte nonce][encrypted data][16-byte auth tag]
// This ensures authenticated encryption with a random nonce per encryption.
func EncryptPrivateKey(pemData []byte) ([]byte, error) {
	key, err := getMasterKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get master key: %w", err)
	}

	// Create AES-256 cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode (provides authentication)
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt and authenticate
	// gcm.Seal appends the ciphertext and auth tag to nonce
	ciphertext := gcm.Seal(nonce, nonce, pemData, nil)

	return ciphertext, nil
}

// DecryptPrivateKey decrypts data encrypted with EncryptPrivateKey.
// Expects format: [12-byte nonce][encrypted data][16-byte auth tag]
func DecryptPrivateKey(encryptedData []byte) ([]byte, error) {
	key, err := getMasterKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get master key: %w", err)
	}

	// Create AES-256 cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(encryptedData) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	// Extract nonce and ciphertext
	nonce, ciphertext := encryptedData[:nonceSize], encryptedData[nonceSize:]

	// Decrypt and verify authentication tag
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}

// ResetMasterKeyForTesting resets the master key singleton for testing purposes.
// This should ONLY be used in tests.
func ResetMasterKeyForTesting() {
	masterKeyOnce = sync.Once{}
	masterKey = nil
}
