package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/aussiebroadwan/bartab/internal/auth/domain"
	"github.com/aussiebroadwan/bartab/internal/auth/store"
	"github.com/aussiebroadwan/bartab/internal/auth/store/drivers/sqlite/gen"
	_ "modernc.org/sqlite"
)

type Store struct {
	db  *sql.DB
	q   *gen.Queries
	dsn string
}

func NewStore(dsn string) (*Store, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}

	// Enforce FKs
	if _, err := db.ExecContext(context.Background(), `PRAGMA foreign_keys = ON;`); err != nil {
		_ = db.Close()
		return nil, err
	}

	return &Store{
		db:  db,
		q:   gen.New(db),
		dsn: dsn,
	}, nil
}

func (s *Store) Close() error { return s.db.Close() }

// Ping verifies the database connection is still alive.
func (s *Store) Ping(ctx context.Context) error {
	return s.db.PingContext(ctx)
}

// Tx starts a read/write transaction and returns a Tx-scoped Store.
func (s *Store) Tx(ctx context.Context) (store.Tx, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	return newTx(tx), nil
}

// WithTx executes fn within a transaction, automatically handling commit/rollback.
func (s *Store) WithTx(ctx context.Context, fn func(tx store.Tx) error) error {
	tx, err := s.Tx(ctx)
	if err != nil {
		return err
	}

	// Ensure rollback is called if we panic or return early with error
	defer func() {
		_ = tx.Rollback() // safe to call even after commit
	}()

	// Execute the function
	if err := fn(tx); err != nil {
		return err // rollback happens in defer
	}

	// Commit on success
	return tx.Commit()
}

func (s *Store) Users() store.Users                           { return &usersRepo{q: s.q} }
func (s *Store) Clients() store.Clients                       { return &clientsRepo{q: s.q} }
func (s *Store) RefreshTokens() store.RefreshTokens           { return &refreshTokensRepo{q: s.q} }
func (s *Store) Invites() store.Invites                       { return &invitesRepo{q: s.q} }
func (s *Store) Roles() store.Roles                           { return &rolesRepo{q: s.q} }
func (s *Store) BackupCodes() store.BackupCodes               { return &backupCodesRepo{q: s.q} }
func (s *Store) MFASessions() store.MFASessions               { return &mfaSessionsRepo{q: s.q} }
func (s *Store) AuthorizationCodes() store.AuthorizationCodes { return &authorizationCodesRepo{q: s.q} }
func (s *Store) SigningKeys() store.SigningKeys               { return &signingKeysRepo{q: s.q} }

func mapNotFound(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return store.ErrNotFound
	}
	return err
}

func mapNullString(ns sql.NullString) string {
	if ns.Valid {
		return ns.String
	}
	return ""
}

func mapStringNull(s string) sql.NullString {
	if s == "" {
		return sql.NullString{Valid: false}
	}
	return sql.NullString{String: s, Valid: true}
}

func mapNullStringPtr(ns sql.NullString) *string {
	if ns.Valid {
		val := ns.String
		return &val
	}
	return nil
}

func mapOptionalString(s *string) sql.NullString {
	if s == nil {
		return sql.NullString{Valid: false}
	}
	return sql.NullString{String: *s, Valid: true}
}

func mapNullTimePtr(nt sql.NullTime) *time.Time {
	if nt.Valid {
		val := nt.Time
		return &val
	}
	return nil
}

func mapOptionalTime(t *time.Time) sql.NullTime {
	if t == nil {
		return sql.NullTime{Valid: false}
	}
	return sql.NullTime{Time: *t, Valid: true}
}

func mapUser(row gen.User) domain.User {
	var mfaEnabled *time.Time
	if row.MfaEnabled.Valid {
		mfaEnabled = &row.MfaEnabled.Time
	}

	var mfaSecret *string
	if row.MfaSecret.Valid {
		mfaSecret = &row.MfaSecret.String
	}

	return domain.User{
		ID:            row.ID,
		Username:      row.Username,
		PreferredName: row.PreferredName,
		PasswordHash:  row.PasswordHash,
		RoleID:        row.RoleID,
		MFAEnabled:    mfaEnabled,
		MFASecret:     mfaSecret,
		CreatedAt:     row.CreatedAt,
		UpdatedAt:     row.UpdatedAt,
	}
}

func mapClient(row gen.Client) domain.Client {
	return domain.Client{
		ID:         row.ID,
		Name:       row.Name,
		SecretHash: mapNullString(row.SecretHash),
		Scopes:     strings.Split(row.Scopes, " "),
		Protected:  row.Protected,
		CreatedAt:  row.CreatedAt,
		UpdatedAt:  row.UpdatedAt,
	}
}

func mapRefreshToken(row gen.RefreshToken) domain.RefreshToken {
	return domain.RefreshToken{
		ID:        row.ID,
		UserID:    row.UserID,
		ClientID:  row.ClientID,
		TokenHash: row.TokenHash,
		SessionID: row.SessionID,
		Scopes:    strings.Split(row.Scopes, " "),
		AMR:       strings.Split(row.Amr, " "),
		ExpiresAt: row.ExpiresAt,
		Revoked:   row.Revoked,
		CreatedAt: row.CreatedAt,
		UpdatedAt: row.UpdatedAt,
	}
}

func mapInvite(row gen.Invite) domain.Invite {
	return domain.Invite{
		ID:        row.ID,
		TokenHash: row.TokenHash,
		ClientID:  row.ClientID,
		CreatedBy: row.CreatedBy,
		RoleID:    row.RoleID,
		ExpiresAt: row.ExpiresAt,
		Reusable:  row.Reusable,
		Used:      row.Used,
		UsedBy:    mapNullString(row.UsedBy),
		CreatedAt: row.CreatedAt,
		UpdatedAt: row.UpdatedAt,
	}
}

func mapRole(row gen.Role) domain.Role {
	return domain.Role{
		ID:        row.ID,
		Name:      row.Name,
		Scopes:    strings.Split(row.Scopes, " "),
		CreatedAt: row.CreatedAt,
		UpdatedAt: row.UpdatedAt,
	}
}

func mapAuthorizationCode(row gen.AuthorizationCode) domain.AuthorizationCode {
	return domain.AuthorizationCode{
		ID:                  row.ID,
		UserID:              row.UserID,
		ClientID:            row.ClientID,
		CodeHash:            row.CodeHash,
		RedirectURI:         row.RedirectUri,
		Scopes:              splitAndFilter(row.Scopes),
		SessionID:           row.SessionID,
		AMR:                 splitAndFilter(row.Amr),
		CodeChallenge:       row.CodeChallenge,
		CodeChallengeMethod: row.CodeChallengeMethod,
		MFASessionID:        mapNullStringPtr(row.MfaSessionID),
		ExpiresAt:           row.ExpiresAt,
		UsedAt:              mapNullTimePtr(row.UsedAt),
		CreatedAt:           row.CreatedAt,
	}
}

func splitAndFilter(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	parts := strings.Fields(s)
	out := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, part := range parts {
		if _, ok := seen[part]; ok {
			continue
		}
		seen[part] = struct{}{}
		out = append(out, part)
	}
	return out
}

func mapSigningKey(row gen.SigningKey) domain.SigningKey {
	return domain.SigningKey{
		ID:                  row.ID,
		Kid:                 row.Kid,
		Algorithm:           row.Algorithm,
		PrivateKeyEncrypted: row.PrivateKeyEncrypted,
		CreatedAt:           row.CreatedAt,
		RetiredAt:           mapNullTimePtr(row.RetiredAt),
		ExpiresAt:           row.ExpiresAt,
	}
}
