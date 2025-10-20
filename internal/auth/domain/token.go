package domain

import "time"

// TokenPair represents what the token endpoint returns the short-lived access
// token (JWT) and the opaque refresh token.
type TokenPair struct {
	AccessToken  string        `json:"access_token"`
	RefreshToken string        `json:"refresh_token"`
	TokenType    string        `json:"token_type,omitempty"` // typically "Bearer"
	ExpiresIn    time.Duration `json:"expires_in"`           // seconds until expiry
	Scope        string        `json:"scope,omitempty"`      // space-delimited
}

// RefreshToken models the stored refresh token record in the DB.
type RefreshToken struct {
	ID        string
	UserID    string
	ClientID  string
	TokenHash string // deterministic fingerprint (base64url SHA-256)
	SessionID string // Session ID (SID) that persists across token refreshes
	Scopes    []string
	AMR       []string // Authentication Method Reference history
	ExpiresAt time.Time
	Revoked   bool
	CreatedAt time.Time
	UpdatedAt time.Time
}

// AccessTokenClaims are the claims we embed in the JWT.
type AccessTokenClaims struct {
	UserID string   `json:"sub"`
	Scopes []string `json:"scp"`
	AMR    []string `json:"amr,omitempty"` // Authentication Method Reference
	Exp    int64    `json:"exp"`
	Iat    int64    `json:"iat"`
	Iss    string   `json:"iss"`
	Aud    []string `json:"aud"`
}
