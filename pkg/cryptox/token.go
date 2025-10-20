package cryptox

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// Token size constants (in bytes before encoding).
const (
	// TokenSize128 provides 128 bits of entropy (22 chars base64url).
	TokenSize128 = 16
	// TokenSize256 provides 256 bits of entropy (43 chars base64url).
	TokenSize256 = 32
	// TokenSize512 provides 512 bits of entropy (86 chars base64url).
	TokenSize512 = 64
)

// GenerateToken creates a cryptographically secure random token of the specified byte length.
// The token is returned as a base64url-encoded string (URL-safe, no padding).
// Returns an error if the random number generator fails.
//
// Common sizes:
//   - TokenSize128 (16 bytes): Short-lived tokens, CSRF tokens
//   - TokenSize256 (32 bytes): OAuth refresh tokens, API keys (recommended)
//   - TokenSize512 (64 bytes): High-security tokens
func GenerateToken(size int) (string, error) {
	if size <= 0 {
		return "", fmt.Errorf("token size must be positive, got %d", size)
	}

	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("failed to generate random token: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// MustGenerateToken is like GenerateToken but panics on error.
// Use this only during initialization or in contexts where failure is unrecoverable.
func MustGenerateToken(size int) string {
	token, err := GenerateToken(size)
	if err != nil {
		panic(fmt.Sprintf("cryptox: failed to generate token: %v", err))
	}
	return token
}

// FingerprintToken returns a deterministic SHA-256 fingerprint of a token.
// This is used to store hashed tokens in databases, allowing lookup without
// storing the original token value.
//
// The fingerprint is returned as a base64url-encoded string (43 chars).
func FingerprintToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
