package sqlite

import (
	"context"
	"strings"
	"time"

	"github.com/aussiebroadwan/bartab/internal/auth/domain"
	"github.com/aussiebroadwan/bartab/internal/auth/store/drivers/sqlite/gen"
)

type mfaSessionsRepo struct {
	q *gen.Queries
}

func (r *mfaSessionsRepo) CreateMFASession(ctx context.Context, session domain.MFASession) error {
	expiresAt, err := time.Parse(time.RFC3339, session.ExpiresAt)
	if err != nil {
		return err
	}

	return r.q.CreateMFASession(ctx, gen.CreateMFASessionParams{
		ID:        session.ID,
		UserID:    session.UserID,
		ClientID:  session.ClientID,
		Scopes:    strings.Join(session.Scopes, " "),
		Amr:       strings.Join(session.AMR, " "),
		SessionID: session.SessionID,
		ExpiresAt: expiresAt,
	})
}

func (r *mfaSessionsRepo) GetMFASession(ctx context.Context, mfaToken string) (domain.MFASession, error) {
	row, err := r.q.GetMFASession(ctx, mfaToken)
	if err != nil {
		return domain.MFASession{}, mapNotFound(err)
	}

	return domain.MFASession{
		ID:        row.ID,
		UserID:    row.UserID,
		ClientID:  row.ClientID,
		Scopes:    strings.Split(row.Scopes, " "),
		AMR:       strings.Split(row.Amr, " "),
		SessionID: row.SessionID,
		Attempts:  int(row.Attempts),
		CreatedAt: row.CreatedAt.Format(time.RFC3339),
		ExpiresAt: row.ExpiresAt.Format(time.RFC3339),
	}, nil
}

func (r *mfaSessionsRepo) IncrementMFASessionAttempts(ctx context.Context, mfaToken string) (domain.MFASession, error) {
	row, err := r.q.IncrementMFASessionAttempts(ctx, mfaToken)
	if err != nil {
		return domain.MFASession{}, mapNotFound(err)
	}

	return domain.MFASession{
		ID:        row.ID,
		UserID:    row.UserID,
		ClientID:  row.ClientID,
		Scopes:    strings.Split(row.Scopes, " "),
		AMR:       strings.Split(row.Amr, " "),
		SessionID: row.SessionID,
		Attempts:  int(row.Attempts),
		CreatedAt: row.CreatedAt.Format(time.RFC3339),
		ExpiresAt: row.ExpiresAt.Format(time.RFC3339),
	}, nil
}

func (r *mfaSessionsRepo) DeleteMFASession(ctx context.Context, mfaToken string) error {
	return r.q.DeleteMFASession(ctx, mfaToken)
}

func (r *mfaSessionsRepo) DeleteExpiredMFASessions(ctx context.Context) error {
	return r.q.DeleteExpiredMFASessions(ctx)
}
