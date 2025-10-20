package sqlite

import (
	"context"
	"strings"

	"github.com/aussiebroadwan/bartab/internal/auth/domain"
	"github.com/aussiebroadwan/bartab/internal/auth/store/drivers/sqlite/gen"
)

type authorizationCodesRepo struct {
	q *gen.Queries
}

func (r *authorizationCodesRepo) CreateAuthorizationCode(ctx context.Context, code domain.AuthorizationCode) error {
	return r.q.CreateAuthorizationCode(ctx, gen.CreateAuthorizationCodeParams{
		ID:                  code.ID,
		UserID:              code.UserID,
		ClientID:            code.ClientID,
		CodeHash:            code.CodeHash,
		RedirectUri:         code.RedirectURI,
		Scopes:              strings.Join(code.Scopes, " "),
		SessionID:           code.SessionID,
		Amr:                 strings.Join(code.AMR, " "),
		CodeChallenge:       code.CodeChallenge,
		CodeChallengeMethod: code.CodeChallengeMethod,
		MfaSessionID:        mapOptionalString(code.MFASessionID),
		ExpiresAt:           code.ExpiresAt,
	})
}

func (r *authorizationCodesRepo) GetAuthorizationCodeByHash(ctx context.Context, hash string) (domain.AuthorizationCode, error) {
	row, err := r.q.GetAuthorizationCodeByHash(ctx, hash)
	if err != nil {
		return domain.AuthorizationCode{}, mapNotFound(err)
	}
	return mapAuthorizationCode(row), nil
}

func (r *authorizationCodesRepo) MarkAuthorizationCodeUsed(ctx context.Context, id string) error {
	return mapNotFound(r.q.MarkAuthorizationCodeUsed(ctx, id))
}

func (r *authorizationCodesRepo) DeleteExpiredAuthorizationCodes(ctx context.Context) error {
	return r.q.DeleteExpiredAuthorizationCodes(ctx)
}
