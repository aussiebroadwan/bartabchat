package sqlite

import (
	"context"

	"github.com/aussiebroadwan/bartab/internal/auth/domain"
	"github.com/aussiebroadwan/bartab/internal/auth/store/drivers/sqlite/gen"
)

type signingKeysRepo struct {
	q *gen.Queries
}

func (r *signingKeysRepo) CreateSigningKey(ctx context.Context, key domain.SigningKey) error {
	return r.q.CreateSigningKey(ctx, gen.CreateSigningKeyParams{
		ID:                  key.ID,
		Kid:                 key.Kid,
		Algorithm:           key.Algorithm,
		PrivateKeyEncrypted: key.PrivateKeyEncrypted,
		CreatedAt:           key.CreatedAt,
		ExpiresAt:           key.ExpiresAt,
	})
}

func (r *signingKeysRepo) GetSigningKeyByKid(ctx context.Context, kid string) (domain.SigningKey, error) {
	row, err := r.q.GetSigningKeyByKid(ctx, kid)
	if err != nil {
		return domain.SigningKey{}, mapNotFound(err)
	}
	return mapSigningKey(row), nil
}

func (r *signingKeysRepo) ListActiveSigningKeys(ctx context.Context) ([]domain.SigningKey, error) {
	rows, err := r.q.ListActiveSigningKeys(ctx)
	if err != nil {
		return nil, err
	}

	keys := make([]domain.SigningKey, len(rows))
	for i, row := range rows {
		keys[i] = mapSigningKey(row)
	}
	return keys, nil
}

func (r *signingKeysRepo) ListAllSigningKeys(ctx context.Context) ([]domain.SigningKey, error) {
	rows, err := r.q.ListAllSigningKeys(ctx)
	if err != nil {
		return nil, err
	}

	keys := make([]domain.SigningKey, len(rows))
	for i, row := range rows {
		keys[i] = mapSigningKey(row)
	}
	return keys, nil
}

func (r *signingKeysRepo) RetireSigningKey(ctx context.Context, kid string) error {
	return r.q.RetireSigningKey(ctx, kid)
}

func (r *signingKeysRepo) DeleteExpiredSigningKeys(ctx context.Context) error {
	return r.q.DeleteExpiredSigningKeys(ctx)
}
