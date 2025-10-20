package sqlite

import (
	"context"

	"github.com/aussiebroadwan/bartab/internal/auth/domain"
	"github.com/aussiebroadwan/bartab/internal/auth/store/drivers/sqlite/gen"
)

type invitesRepo struct {
	q *gen.Queries
}

func (r *invitesRepo) CreateInvite(ctx context.Context, inv domain.Invite) error {
	return r.q.CreateInvite(ctx, gen.CreateInviteParams{
		ID:        inv.ID,
		TokenHash: inv.TokenHash,
		ClientID:  inv.ClientID,
		CreatedBy: inv.CreatedBy,
		RoleID:    inv.RoleID,
		ExpiresAt: inv.ExpiresAt,
		Reusable:  inv.Reusable,
	})
}

func (r *invitesRepo) GetActiveInviteByTokenHash(
	ctx context.Context,
	hash string,
) (domain.Invite, error) {
	row, err := r.q.GetActiveInviteByTokenHash(ctx, hash)
	if err != nil {
		return domain.Invite{}, mapNotFound(err)
	}
	return mapInvite(row), nil
}

func (r *invitesRepo) MarkInviteUsed(
	ctx context.Context,
	inviteID string,
	usedByUserID string,
) error {
	return r.q.MarkInviteUsed(ctx, gen.MarkInviteUsedParams{
		UsedBy: mapStringNull(usedByUserID),
		ID:     inviteID,
	})
}

func (r *invitesRepo) DeleteExpiredInvites(ctx context.Context) error {
	return r.q.DeleteExpiredInvites(ctx)
}
