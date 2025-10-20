package jwtx

import (
	"crypto/rand"
	"encoding/base64"
	"slices"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Default token TTL constants for standard OAuth2/JWT flows.
// These provide sensible security defaults but can be overridden per-service.
const (
	// DefaultAccessTokenTTL is the default lifetime for access tokens.
	// Short-lived for security - typical range is 15m to 1h.
	DefaultAccessTokenTTL = 15 * time.Minute

	// DefaultRefreshTokenTTL is the default lifetime for refresh tokens.
	// Longer-lived for user convenience - typical range is 7d to 30d.
	DefaultRefreshTokenTTL = 7 * 24 * time.Hour
)

// Claims are access-token claims used across service, we are keeping
// additive changes to preserve compatibility for later.
type Claims struct {
	jwt.RegisteredClaims

	/* Cross-service custom fields */

	// Session ID
	SID string `json:"sid,omitempty"`

	// Permission Scopes "chat:read, chat:write"
	Scopes []string `json:"scopes,omitempty"`

	// Authentication Methods Reference ["pwd","mfa"]
	// 		"pwd": Password-based Authentication
	//		"otp": One-time Password (e.g. TOTP)
	//		"mfa": Multi-factor Auth was used
	// This is mainly for debugging purposes but can help with locking
	// access to require MFA for admin tasks.
	AMR []string `json:"amr,omitempty"`

	// Username for the authenticated user
	Username string `json:"username,omitempty"`

	// PreferredName is the display name for the user
	PreferredName string `json:"preferred_name,omitempty"`
}

// NewAccessClaims builds minimally-correct claims.
func NewAccessClaims(
	subject, sid string,
	scopes, amr []string,
	ttl time.Duration,
	issuer string,
	audience []string,
	username, preferredName string,
	now time.Time,
) Claims {
	return Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   subject,
			Audience:  jwt.ClaimStrings(audience),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			ID:        NewJTI(),
		},
		SID:           sid,
		Scopes:        scopes,
		AMR:           amr,
		Username:      username,
		PreferredName: preferredName,
	}
}

// NewJTI returns a URL-safe random identifier for the "jti" claim. There
// might be a better way of doing this, but I'm being lazy and using random.
func NewJTI() string {
	var b [20]byte
	_, _ = rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}

// ValidateIssuer checks if the issuer matches expected value.
func (c *Claims) ValidateIssuer(expected string) error {
	if expected == "" {
		return nil // nothing to enforce
	}

	if c.Issuer != expected {
		return ErrIssuer
	}

	return nil
}

// ValidateAudience checks if at least one expected audience is present.
func (c *Claims) ValidateAudience(expected []string) error {
	if len(expected) == 0 {
		return nil // nothing to enforce
	}

	for _, want := range expected {
		if slices.Contains(c.Audience, want) {
			return nil
		}
	}

	return ErrAudience
}

// ValidateExpiry ensures the token hasn’t expired (exp) and isn’t before nbf.
func (c *Claims) ValidateExpiry() error {
	now := time.Now().UTC()

	// Check expired (exp)
	if c.ExpiresAt != nil && now.After(c.ExpiresAt.Time) {
		return ErrExpired
	}

	// Check if a valid token isn't used before it is valid (nbf)
	if c.NotBefore != nil && now.Before(c.NotBefore.Time) {
		return ErrNotYetValid
	}

	return nil
}

// ValidateExpiryWithLeeway adds a small grace period for clock skew.
func (c *Claims) ValidateExpiryWithLeeway(leeway time.Duration) error {
	now := time.Now().UTC()

	// Check After Leeway
	if c.ExpiresAt != nil && now.After(c.ExpiresAt.Add(leeway)) {
		return ErrExpired
	}

	// Check Before Leeway
	if c.NotBefore != nil && now.Before(c.NotBefore.Add(-leeway)) {
		return ErrNotYetValid
	}

	return nil
}
