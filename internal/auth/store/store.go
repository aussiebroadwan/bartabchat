package store

import (
	"context"
	"errors"

	"github.com/aussiebroadwan/bartab/internal/auth/domain"
)

var (
	ErrNotFound      = errors.New("store: not found")
	ErrAlreadyExists = errors.New("store: already exists")
)

// Store is the root data access interface. Concrete drivers (sqlite, postgres)
// implement this. It exposes sub-repositories to keep concerns tidy and
// testable. We can change having the sub-repos as methods later but we do it
// now so we can have more control and actively stop people from accidently
// doing transactions within transactions.
type Store interface {
	Users() Users
	Clients() Clients
	RefreshTokens() RefreshTokens
	Invites() Invites
	Roles() Roles
	BackupCodes() BackupCodes
	MFASessions() MFASessions
	AuthorizationCodes() AuthorizationCodes
	SigningKeys() SigningKeys

	ApplyMigrations() error

	// Tx starts a read/write transaction and returns a Tx-scoped Store.
	// Use it for multi-step operations that must be atomic (e.g., refresh rotation).
	// The caller MUST call Commit() or Rollback() on the returned Tx.
	Tx(ctx context.Context) (Tx, error)

	// WithTx executes a function within a transaction.
	// If fn returns an error, the transaction is rolled back.
	// If fn returns nil, the transaction is committed.
	// This is the recommended way to handle transactions as it automatically
	// handles commit/rollback logic.
	WithTx(ctx context.Context, fn func(tx Tx) error) error

	// Close releases any underlying resources (optional for sqlite).
	Close() error

	// Ping verifies the database connection is still alive.
	Ping(ctx context.Context) error
}

// Tx is a transactional store. It embeds the same repos but adds Commit/Rollback.
type Tx interface {
	Store
	Commit() error
	Rollback() error
}

type Users interface {
	// GetUserByID returns a user by id.
	GetUserByID(ctx context.Context, id string) (domain.User, error)

	// GetUserByUsername is used during password grant.
	GetUserByUsername(ctx context.Context, username string) (domain.User, error)

	// CreateUser inserts a new user (id is provided by app via ULID).
	CreateUser(ctx context.Context, u domain.User) error

	// UpdatePreferredName mutates the preferred_name and bumps updated_at.
	UpdatePreferredName(ctx context.Context, userID string, preferredName string) error

	// UpdatePasswordHash sets the password_hash (argon2) and bumps updated_at.
	UpdatePasswordHash(ctx context.Context, userID string, newHash string) error

	// DeleteUser cascades to refresh_tokens (per schema).
	DeleteUser(ctx context.Context, userID string) error

	// IsEmpty returns true if there are no users.
	IsEmpty(ctx context.Context) (bool, error)

	// UpdateMFASecret sets the MFA secret for a user.
	UpdateMFASecret(ctx context.Context, userID string, secret string) error

	// EnableMFA marks MFA as enabled for a user (sets mfa_enabled timestamp).
	EnableMFA(ctx context.Context, userID string) error

	// DisableMFA disables MFA for a user (clears mfa_enabled and mfa_secret).
	DisableMFA(ctx context.Context, userID string) error

	// GetMFAInfo returns the MFA-related fields for a user.
	GetMFAInfo(ctx context.Context, userID string) (mfaEnabled *string, mfaSecret *string, err error)
}

type Clients interface {
	// GetClientByID fetches a client (for password/client_credentials grants).
	GetClientByID(ctx context.Context, id string) (domain.Client, error)

	// ListClients returns all clients ordered by creation date (newest first).
	ListClients(ctx context.Context) ([]domain.Client, error)

	// CreateClient inserts a new client (id is ULID; secret_hash may be empty for public clients).
	CreateClient(ctx context.Context, c domain.Client) error

	UpdateClientSecretHash(ctx context.Context, clientID, secretHash string) error
	UpdateClientScopes(ctx context.Context, clientID string, scopes []string) error
	UpdateClientName(ctx context.Context, clientID, name string) error

	// DeleteClient cascades to refresh_tokens (per schema).
	DeleteClient(ctx context.Context, clientID string) error

	// IsEmpty returns true if there are no clients.
	IsEmpty(ctx context.Context) (bool, error)
}

type RefreshTokens interface {
	// CreateRefreshToken stores a new refresh token record.
	CreateRefreshToken(ctx context.Context, t domain.RefreshToken) error

	// GetRefreshTokenByHash returns the token by its hashed value (argon2).
	GetRefreshTokenByHash(ctx context.Context, hash string) (domain.RefreshToken, error)

	// RevokeRefreshToken flips revoked=1, sets updated_at.
	RevokeRefreshToken(ctx context.Context, hash string) error

	// RevokeAllUserClientRefreshTokens bulk revocation for a user+client pair (e.g., password reset).
	RevokeAllUserClientRefreshTokens(ctx context.Context, userID, clientID string) error

	// DeleteExpiredRefreshTokens is optional housekeeping.
	DeleteExpiredRefreshTokens(ctx context.Context) error
}

type Invites interface {
	// CreateInvite writes a new invite (token_hash is argon2 of the opaque invite token).
	CreateInvite(ctx context.Context, inv domain.Invite) error

	// GetActiveInviteByTokenHash returns a not-used, not-expired invite by hash.
	GetActiveInviteByTokenHash(ctx context.Context, hash string) (domain.Invite, error)

	// MarkInviteUsed sets used=1, used_by=userID, updated_at=now (transaction-friendly).
	MarkInviteUsed(ctx context.Context, inviteID string, usedByUserID string) error

	// DeleteExpiredInvites is optional housekeeping.
	DeleteExpiredInvites(ctx context.Context) error
}

type Bootstrap interface {
	// IsEmpty returns true if there are no users or clients.
	IsEmpty(ctx context.Context) (bool, error)
}

type Roles interface {
	// GetRoleByID fetches a role by its ID
	GetRoleByID(ctx context.Context, id string) (domain.Role, error)

	// GetRoleByName fetches a role by its name (for bootstrap)
	GetRoleByName(ctx context.Context, name string) (domain.Role, error)

	// ListAll returns all roles in the system
	ListAll(ctx context.Context) ([]domain.Role, error)

	// CreateRole inserts a new role (id is ULID)
	CreateRole(ctx context.Context, r domain.Role) error

	// UpdateRoleScopes modifies the scopes for a role
	UpdateRoleScopes(ctx context.Context, roleID string, scopes []string) error

	// DeleteRole removes a role (should fail if users still reference it)
	DeleteRole(ctx context.Context, roleID string) error

	// IsEmpty returns true if there are no roles
	IsEmpty(ctx context.Context) (bool, error)
}

type BackupCodes interface {
	// CreateBackupCode stores a backup code hash for a user.
	CreateBackupCode(ctx context.Context, userID string, codeHash string) error

	// VerifyBackupCode checks if a backup code hash exists for a user.
	VerifyBackupCode(ctx context.Context, userID string, codeHash string) (bool, error)

	// DeleteBackupCode removes a specific backup code after use.
	DeleteBackupCode(ctx context.Context, userID string, codeHash string) error

	// DeleteAllBackupCodes removes all backup codes for a user.
	DeleteAllBackupCodes(ctx context.Context, userID string) error

	// CountUserBackupCodes returns the number of backup codes for a user.
	CountUserBackupCodes(ctx context.Context, userID string) (int, error)
}

type MFASessions interface {
	// CreateMFASession creates a new MFA challenge session.
	CreateMFASession(ctx context.Context, session domain.MFASession) error

	// GetMFASession retrieves an MFA session by its token (only if not expired).
	GetMFASession(ctx context.Context, mfaToken string) (domain.MFASession, error)

	// IncrementMFASessionAttempts increments the failed attempt counter for an MFA session.
	// Returns the updated MFASession with the new attempt count.
	IncrementMFASessionAttempts(ctx context.Context, mfaToken string) (domain.MFASession, error)

	// DeleteMFASession removes an MFA session by its token.
	DeleteMFASession(ctx context.Context, mfaToken string) error

	// DeleteExpiredMFASessions removes all expired MFA sessions (housekeeping).
	DeleteExpiredMFASessions(ctx context.Context) error
}

type AuthorizationCodes interface {
	// CreateAuthorizationCode stores a freshly minted authorization code.
	CreateAuthorizationCode(ctx context.Context, code domain.AuthorizationCode) error

	// GetAuthorizationCodeByHash fetches a code by its hashed value when redeeming.
	GetAuthorizationCodeByHash(ctx context.Context, hash string) (domain.AuthorizationCode, error)

	// MarkAuthorizationCodeUsed marks a code as consumed to prevent re-use.
	MarkAuthorizationCodeUsed(ctx context.Context, id string) error

	// DeleteExpiredAuthorizationCodes removes any codes that are no longer valid.
	DeleteExpiredAuthorizationCodes(ctx context.Context) error
}

type SigningKeys interface {
	// CreateSigningKey stores a new signing key with encrypted private key material.
	CreateSigningKey(ctx context.Context, key domain.SigningKey) error

	// GetSigningKeyByKid fetches a signing key by its key identifier.
	GetSigningKeyByKid(ctx context.Context, kid string) (domain.SigningKey, error)

	// ListActiveSigningKeys returns all non-retired, non-expired signing keys
	// ordered by creation date (newest first).
	ListActiveSigningKeys(ctx context.Context) ([]domain.SigningKey, error)

	// ListAllSigningKeys returns all signing keys (including retired and expired)
	// ordered by creation date (newest first). Used for verification during grace period.
	ListAllSigningKeys(ctx context.Context) ([]domain.SigningKey, error)

	// RetireSigningKey marks a key as retired (sets retired_at timestamp).
	// Retired keys can still be used for verification but not for signing.
	RetireSigningKey(ctx context.Context, kid string) error

	// DeleteExpiredSigningKeys removes all keys that have passed their expires_at timestamp.
	// This is housekeeping to prevent unbounded growth of the signing_keys table.
	DeleteExpiredSigningKeys(ctx context.Context) error
}
