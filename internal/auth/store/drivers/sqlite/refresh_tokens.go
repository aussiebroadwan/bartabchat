package sqlite

import (
	"context"
	"strings"

	"github.com/aussiebroadwan/bartab/internal/auth/domain"
	"github.com/aussiebroadwan/bartab/internal/auth/store/drivers/sqlite/gen"
)

type refreshTokensRepo struct {
	q *gen.Queries
}

func (r *refreshTokensRepo) CreateRefreshToken(ctx context.Context, t domain.RefreshToken) error {
	return r.q.CreateRefreshToken(ctx, gen.CreateRefreshTokenParams{
		ID:        t.ID,
		UserID:    t.UserID,
		ClientID:  t.ClientID,
		TokenHash: t.TokenHash,
		SessionID: t.SessionID,
		Scopes:    strings.Join(t.Scopes, " "),
		Amr:       strings.Join(t.AMR, " "),
		ExpiresAt: t.ExpiresAt,
	})
}

func (r *refreshTokensRepo) GetRefreshTokenByHash(
	ctx context.Context,
	hash string,
) (domain.RefreshToken, error) {
	row, err := r.q.GetRefreshTokenByHash(ctx, hash)
	if err != nil {
		return domain.RefreshToken{}, mapNotFound(err)
	}
	return mapRefreshToken(row), nil
}

func (r *refreshTokensRepo) RevokeRefreshToken(ctx context.Context, hash string) error {
	return r.q.RevokeRefreshToken(ctx, hash)
}

func (r *refreshTokensRepo) RevokeAllUserClientRefreshTokens(
	ctx context.Context,
	userID, clientID string,
) error {
	return r.q.RevokeAllUserClientRefreshTokens(ctx, gen.RevokeAllUserClientRefreshTokensParams{
		UserID:   userID,
		ClientID: clientID,
	})
}

func (r *refreshTokensRepo) DeleteExpiredRefreshTokens(ctx context.Context) error {
	return r.q.DeleteExpiredRefreshTokens(ctx)
}
