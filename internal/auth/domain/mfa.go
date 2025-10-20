package domain

// MFAChallengeResponse is returned when MFA is required during authentication
type MFAChallengeResponse struct {
	MFARequired bool     `json:"mfa_required"` // always true
	MFAToken    string   `json:"mfa_token"`    // ULID reference token
	Methods     []string `json:"methods"`      // available MFA methods (e.g., ["totp", "backup_codes"])
}

// MFASession represents a pending MFA challenge session
type MFASession struct {
	ID        string   // ULID (the mfa_token)
	UserID    string   // User ID
	ClientID  string   // Client ID
	Scopes    []string // Requested scopes
	AMR       []string // Authentication Method References
	SessionID string   // Session ID for future refresh token
	Attempts  int      // Number of failed MFA attempts (max 5 to prevent brute force)
	CreatedAt string   // ISO8601 timestamp
	ExpiresAt string   // ISO8601 timestamp
}

type MFAEnrollResponse struct {
	Secret  string // Base32 encoded secret for TOTP
	QRCode  string // otpauth:// URL for QR code generation
	Issuer  string // Issuer name (e.g., service name)
	Account string // Account name (e.g., user email)
}
