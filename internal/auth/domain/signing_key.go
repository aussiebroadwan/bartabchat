package domain

import "time"

// SigningKey represents a JWT signing key stored in the database with support for key rotation.
// Keys are encrypted at rest and can be marked as retired while remaining valid for
// verification during a grace period.
type SigningKey struct {
	ID                  string     // ULID
	Kid                 string     // Key identifier in JWKS (e.g., "bartab-abc123")
	Algorithm           string     // RS256, ES256, or EdDSA
	PrivateKeyEncrypted []byte     // AES-256-GCM encrypted private key PEM
	CreatedAt           time.Time  // When the key was created
	RetiredAt           *time.Time // When key was retired from active signing (nil = active)
	ExpiresAt           time.Time  // Hard deletion after this (for cleanup)
}

// IsActive returns true if the key is not retired and not expired.
func (k *SigningKey) IsActive(now time.Time) bool {
	return k.RetiredAt == nil && now.Before(k.ExpiresAt)
}

// IsExpired returns true if the key has passed its expiration time.
func (k *SigningKey) IsExpired(now time.Time) bool {
	return now.After(k.ExpiresAt)
}
