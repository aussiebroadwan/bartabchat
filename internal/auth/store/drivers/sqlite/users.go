package sqlite

import (
	"context"
	"database/sql"

	"github.com/aussiebroadwan/bartab/internal/auth/domain"
	"github.com/aussiebroadwan/bartab/internal/auth/store/drivers/sqlite/gen"
)

type usersRepo struct {
	q *gen.Queries
}

func (r *usersRepo) GetUserByID(ctx context.Context, id string) (domain.User, error) {
	row, err := r.q.GetUserByID(ctx, id)
	if err != nil {
		return domain.User{}, mapNotFound(err)
	}
	return mapUser(row), nil
}

func (r *usersRepo) GetUserByUsername(ctx context.Context, username string) (domain.User, error) {
	row, err := r.q.GetUserByUsername(ctx, username)
	if err != nil {
		return domain.User{}, mapNotFound(err)
	}
	return mapUser(row), nil
}

func (r *usersRepo) CreateUser(ctx context.Context, u domain.User) error {
	return r.q.CreateUser(ctx, gen.CreateUserParams{
		ID:            u.ID,
		Username:      u.Username,
		PreferredName: u.PreferredName,
		PasswordHash:  u.PasswordHash,
		RoleID:        u.RoleID,
	})
}

func (r *usersRepo) UpdatePreferredName(
	ctx context.Context,
	userID string,
	preferredName string,
) error {
	return r.q.UpdateUserPreferredName(ctx, gen.UpdateUserPreferredNameParams{
		PreferredName: preferredName,
		ID:            userID,
	})
}

func (r *usersRepo) UpdatePasswordHash(ctx context.Context, userID string, newHash string) error {
	return r.q.UpdateUserPasswordHash(ctx, gen.UpdateUserPasswordHashParams{
		PasswordHash: newHash,
		ID:           userID,
	})
}

func (r *usersRepo) DeleteUser(ctx context.Context, userID string) error {
	return r.q.DeleteUser(ctx, userID)
}

func (r *usersRepo) IsEmpty(ctx context.Context) (bool, error) {
	count, err := r.q.CountUsers(ctx)
	if err != nil {
		return false, err
	}
	return count == 0, nil
}

func (r *usersRepo) UpdateMFASecret(ctx context.Context, userID string, secret string) error {
	return r.q.UpdateUserMFASecret(ctx, gen.UpdateUserMFASecretParams{
		MfaSecret: stringToNullString(secret),
		ID:        userID,
	})
}

func (r *usersRepo) EnableMFA(ctx context.Context, userID string) error {
	return r.q.EnableUserMFA(ctx, userID)
}

func (r *usersRepo) DisableMFA(ctx context.Context, userID string) error {
	return r.q.DisableUserMFA(ctx, userID)
}

func (r *usersRepo) GetMFAInfo(ctx context.Context, userID string) (mfaEnabled *string, mfaSecret *string, err error) {
	row, err := r.q.GetUserMFAInfo(ctx, userID)
	if err != nil {
		return nil, nil, mapNotFound(err)
	}

	var enabledStr *string
	if row.MfaEnabled.Valid {
		str := row.MfaEnabled.Time.Format("2006-01-02T15:04:05Z07:00")
		enabledStr = &str
	}

	var secretStr *string
	if row.MfaSecret.Valid {
		secretStr = &row.MfaSecret.String
	}

	return enabledStr, secretStr, nil
}

func stringToNullString(s string) sql.NullString {
	if s == "" {
		return sql.NullString{Valid: false}
	}
	return sql.NullString{String: s, Valid: true}
}
