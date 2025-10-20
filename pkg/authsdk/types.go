package authsdk

import (
	"github.com/aussiebroadwan/bartab/pkg/jwtx"
)

// ============================================================================
// Internal Response Types (used for JSON unmarshaling)
// ============================================================================

// ErrorResponse represents a standard OAuth2 error response per RFC 6749.
// This is used internally for parsing HTTP error responses.
// Client code should use the OAuth2Error type from errors.go instead.
type ErrorResponse struct {
	// Error is the OAuth2 error code (e.g., "invalid_request", "invalid_grant")
	Error string `json:"error"`

	// ErrorDescription is a human-readable description of the error
	ErrorDescription string `json:"error_description"`
}

// ValidationErrorResponse represents a validation error response.
// This is used internally for parsing HTTP error responses.
// This is returned when request validation fails, typically from the bootstrap endpoint.
type ValidationErrorResponse struct {
	// Code is the error code (e.g., "validation_error")
	Code string `json:"code"`

	// Message is a human-readable error message
	Message string `json:"message"`

	// Details contains field-specific validation errors (field name: error message)
	Details map[string]string `json:"details,omitempty"`
}

// ============================================================================
// Token Types
// ============================================================================

// TokenResponse represents the OAuth2 token endpoint response per RFC 6749.
// This is returned from the POST /v1/oauth2/token endpoint for both password
// and refresh_token grant types.
type TokenResponse struct {
	// AccessToken is the JWT access token used to authenticate API requests
	AccessToken string `json:"access_token"`

	// RefreshToken is the opaque refresh token used to obtain new access tokens
	RefreshToken string `json:"refresh_token,omitempty"`

	// TokenType is always "Bearer" per OAuth2 spec
	TokenType string `json:"token_type"`

	// ExpiresIn is the lifetime in seconds of the access token
	ExpiresIn int `json:"expires_in"`

	// Scope is the space-delimited list of scopes granted to this token
	Scope string `json:"scope,omitempty"`
}

// IntrospectionResponse represents the RFC7662 token introspection response.
// When a token is inactive, only the Active field will be false and other fields will be empty.
type IntrospectionResponse struct {
	Active bool `json:"active"`

	// Optional fields (only present when active=true)
	Scope         string   `json:"scope,omitempty"`
	ClientID      string   `json:"client_id,omitempty"`
	Username      string   `json:"username,omitempty"`
	TokenType     string   `json:"token_type,omitempty"`
	Exp           int64    `json:"exp,omitempty"`
	Iat           int64    `json:"iat,omitempty"`
	Nbf           int64    `json:"nbf,omitempty"`
	Sub           string   `json:"sub,omitempty"`
	Aud           []string `json:"aud,omitempty"`
	Iss           string   `json:"iss,omitempty"`
	Jti           string   `json:"jti,omitempty"`
	SessionID     string   `json:"sid,omitempty"`
	AMR           []string `json:"amr,omitempty"`
	PreferredName string   `json:"preferred_name,omitempty"`
}

// ============================================================================
// Bootstrap Types
// ============================================================================

// BootstrapRequest contains the data needed to bootstrap the auth service.
// It creates an initial admin user and OAuth2 client during service initialization.
type BootstrapRequest struct {
	// AdminUsername is the username for the initial admin user (3-32 chars, alphanumeric with _ or -)
	AdminUsername string `json:"admin_username"`

	// AdminPreferredName is the display name for the admin user (max 64 chars)
	AdminPreferredName string `json:"admin_preferred_name"`

	// AdminPassword is the password for the admin user (8-128 chars)
	AdminPassword string `json:"admin_password"`

	// ClientName is the name for the initial OAuth2 client (max 100 chars, alphanumeric with _ or -)
	ClientName string `json:"client_name"`

	// ClientScopes is a space-delimited list of scopes for the client (e.g., ["profile:read", "users:write"])
	ClientScopes []string `json:"client_scopes"`

	// Roles is a list of role definitions to create during bootstrap (must include "admin" role)
	Roles []RoleDefinition `json:"roles"`
}

// RoleDefinition defines a role's name and its allowed scopes.
type RoleDefinition struct {
	// Name is the role name (e.g., "admin", "user", "readonly")
	Name string `json:"name"`

	// Scopes is a space-delimited list of scopes this role can request
	Scopes []string `json:"scopes"`
}

// BootstrapResponse contains the IDs of the created admin user and client.
type BootstrapResponse struct {
	// AdminUserID is the unique identifier of the created admin user
	AdminUserID string `json:"admin_user_id"`

	// ClientID is the unique identifier of the created OAuth2 client
	ClientID string `json:"client_id"`

	// ClientSecret is the plaintext secret for the created confidential client (only returned once)
	ClientSecret string `json:"client_secret"`
}

// ============================================================================
// User Types
// ============================================================================

// UserInfoResponse represents the OAuth2 UserInfo endpoint response.
//
// This is returned from the GET /v1/userinfo endpoint when a valid access
// token is provided in the Authorization header. Requires 'profile:read' scope.
type UserInfoResponse struct {
	// UserID is the unique identifier for the user
	UserID string `json:"user_id"`

	// Username is the user's login username
	Username string `json:"username"`

	// PreferredName is the user's display name
	PreferredName string `json:"preferred_name"`

	// Role is the name of the user's role
	Role string `json:"role"`
}

// ============================================================================
// Invite Types
// ============================================================================

// InviteRequest represents a request to mint a new invite token.
type InviteRequest struct {
	ClientID  string `json:"client_id"`
	RoleID    string `json:"role_id"`              // Role to assign to the invited user
	ExpiresAt int64  `json:"expires_at,omitempty"` // epoch time in seconds (1 day from creation if omitted)
	Reusable  bool   `json:"reusable,omitempty"`   // default false
}

// InviteResponse contains the minted invite token and its metadata.
type InviteResponse struct {
	InviteToken string `json:"invite_token"`
	ClientID    string `json:"client_id"`
	ExpiresAt   int64  `json:"expires_at"` // epoch time in seconds
}

// RedeemInviteRequest represents a request to redeem an invite token.
type RedeemInviteRequest struct {
	InviteToken string `json:"invite_token"`
	Username    string `json:"username"`
	Password    string `json:"password"`
	ClientID    string `json:"client_id"`
}

// RedeemInviteResponse contains information about the newly created user.
type RedeemInviteResponse struct {
	UserID   string `json:"user_id"`
	Username string `json:"username"`
}

// ============================================================================
// Role Types
// ============================================================================

// RoleInfo represents a single role in the system.
type RoleInfo struct {
	ID     string   `json:"id"`
	Name   string   `json:"name"`
	Scopes []string `json:"scopes"`
}

// ListRolesResponse contains the list of all roles.
type ListRolesResponse struct {
	Roles []RoleInfo `json:"roles"`
}

// ============================================================================
// Client Types
// ============================================================================

// CreateClientRequest represents the request to create a new OAuth2 client.
type CreateClientRequest struct {
	// Name is the human-readable name for the client
	Name string `json:"name"`

	// Confidential indicates whether to create a confidential client with a secret.
	// If true, a secret will be auto-generated and returned once.
	// If false, creates a public client (no secret, cannot use client_credentials grant).
	Confidential bool `json:"confidential"`

	// Scopes is the list of scopes this client is authorized to grant
	Scopes []string `json:"scopes"`
}

// CreateClientResponse contains the created client's ID and secret (if provided).
type CreateClientResponse struct {
	// ClientID is the unique identifier for the created client
	ClientID string `json:"client_id"`

	// ClientSecret is the plaintext secret (only returned once at creation).
	// Will be empty if no secret was provided in the request.
	ClientSecret string `json:"client_secret,omitempty"`
}

// ClientInfo represents information about an OAuth2 client.
type ClientInfo struct {
	// ID is the unique identifier for the client
	ID string `json:"id"`

	// Name is the human-readable name of the client
	Name string `json:"name"`

	// Scopes is the list of scopes this client can grant
	Scopes []string `json:"scopes"`

	// HasSecret indicates whether this client has a secret (confidential client)
	HasSecret bool `json:"has_secret"`

	// Protected indicates whether this client is protected from deletion
	Protected bool `json:"protected"`

	// CreatedAt is the timestamp when the client was created (RFC3339 format)
	CreatedAt string `json:"created_at"`
}

// ListClientsResponse contains a list of OAuth2 clients.
type ListClientsResponse struct {
	Clients []ClientInfo `json:"clients"`
}

// ============================================================================
// Health Types
// ============================================================================

// HealthResponse represents the response structure for health check endpoints.
// Used by both /livez and /readyz endpoints (readyz includes additional Checks field).
type HealthResponse struct {
	// Status indicates the overall health status (e.g., "ok")
	Status string `json:"status"`

	// Uptime is the service uptime duration as a string (e.g., "1h23m45s")
	Uptime string `json:"uptime,omitempty"`

	// Version is the service version string
	Version string `json:"version,omitempty"`

	// Checks contains readiness check results for critical dependencies (only for /readyz)
	Checks *HealthChecks `json:"checks,omitempty"`
}

// HealthChecks represents the status of critical service dependencies.
// Used in the /readyz endpoint to indicate the status of each component.
type HealthChecks struct {
	// Database indicates the database connection status
	Database string `json:"database"`

	// Signer indicates the JWT signing capability status
	Signer string `json:"signer"`
}

// ============================================================================
// JWKS Types
// ============================================================================

// JWKSResponse contains the JSON Web Key Set.
// This is returned from the GET /.well-known/jwks.json endpoint and contains
// public keys used to verify JWT signatures.
type JWKSResponse jwtx.JWKS

// ============================================================================
// MFA Types
// ============================================================================

// TOTPEnrollResponse represents the response from TOTP enrollment.
type TOTPEnrollResponse struct {
	Secret  string `json:"secret" example:"JBSWY3DPEHPK3PXP"`
	QRCode  string `json:"qr_code" example:"otpauth://totp/issuer:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=issuer"`
	Issuer  string `json:"issuer"`
	Account string `json:"account"`
}

// MFAChallengeResponse represents an MFA challenge returned during authentication.
type MFAChallengeResponse struct {
	MFARequired bool     `json:"mfa_required"`
	MFAToken    string   `json:"mfa_token"`
	Methods     []string `json:"methods"`
}

// BackupCodesResponse represents the response from backup code operations.
type BackupCodesResponse struct {
	Codes []string `json:"codes"`
}

// TOTPVerifyRequest is the request to verify a TOTP code.
type TOTPVerifyRequest struct {
	Code string `json:"code"` // 6-digit TOTP code
}

// TOTPRemoveRequest is the request to remove TOTP MFA.
type TOTPRemoveRequest struct {
	Code string `json:"code"` // 6-digit TOTP code for verification
}

// BackupCodesRegenerateRequest is the request to regenerate backup codes.
type BackupCodesRegenerateRequest struct {
	Code string `json:"code"` // 6-digit TOTP code for verification
}

// ============================================================================
// Key Rotation Types
// ============================================================================

// RotateKeyRequest represents a request to rotate signing keys.
type RotateKeyRequest struct {
	// RetireExisting will mark current active keys as retired if true.
	// If false, new key is added alongside existing keys.
	RetireExisting bool `json:"retire_existing"`
}

// SigningKeyInfo represents a JWT signing key with its metadata.
type SigningKeyInfo struct {
	ID        string  `json:"id"`                   // ULID
	Kid       string  `json:"kid"`                  // Key identifier in JWKS
	Algorithm string  `json:"algorithm"`            // RS256, ES256, or EdDSA
	CreatedAt string  `json:"created_at"`           // RFC3339 timestamp
	RetiredAt *string `json:"retired_at,omitempty"` // RFC3339 timestamp (null if active)
	ExpiresAt string  `json:"expires_at"`           // RFC3339 timestamp
}

// RotateKeyResponse represents the result of a key rotation operation.
type RotateKeyResponse struct {
	NewKey      SigningKeyInfo   `json:"new_key"`
	RetiredKeys []SigningKeyInfo `json:"retired_keys,omitempty"`
	ActiveKeys  int              `json:"active_keys"`
}
