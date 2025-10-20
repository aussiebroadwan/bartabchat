package sqlite

import (
	"context"
	"database/sql"
	"errors"

	"github.com/aussiebroadwan/bartab/internal/auth/store/drivers/sqlite/gen"
)

type backupCodesRepo struct {
	q *gen.Queries
}

func (r *backupCodesRepo) CreateBackupCode(ctx context.Context, userID string, codeHash string) error {
	return r.q.CreateBackupCode(ctx, gen.CreateBackupCodeParams{
		UserID:   userID,
		CodeHash: codeHash,
	})
}

func (r *backupCodesRepo) VerifyBackupCode(ctx context.Context, userID string, codeHash string) (bool, error) {
	_, err := r.q.GetBackupCodeHash(ctx, gen.GetBackupCodeHashParams{
		UserID:   userID,
		CodeHash: codeHash,
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (r *backupCodesRepo) DeleteBackupCode(ctx context.Context, userID string, codeHash string) error {
	return r.q.DeleteBackupCode(ctx, gen.DeleteBackupCodeParams{
		UserID:   userID,
		CodeHash: codeHash,
	})
}

func (r *backupCodesRepo) DeleteAllBackupCodes(ctx context.Context, userID string) error {
	return r.q.DeleteAllBackupCodes(ctx, userID)
}

func (r *backupCodesRepo) CountUserBackupCodes(ctx context.Context, userID string) (int, error) {
	count, err := r.q.CountUserBackupCodes(ctx, userID)
	if err != nil {
		return 0, err
	}
	return int(count), nil
}
