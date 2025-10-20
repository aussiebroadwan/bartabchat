package domain

import "time"

// AuthorizationCode represents an OAuth 2.0 authorization code issuance.
type AuthorizationCode struct {
	ID                  string
	UserID              string
	ClientID            string
	CodeHash            string
	RedirectURI         string
	Scopes              []string
	SessionID           string
	AMR                 []string
	CodeChallenge       string
	CodeChallengeMethod string
	MFASessionID        *string
	ExpiresAt           time.Time
	UsedAt              *time.Time
	CreatedAt           time.Time
}
