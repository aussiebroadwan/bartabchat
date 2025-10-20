package sqlite

import (
	"context"
	"strings"

	"github.com/aussiebroadwan/bartab/internal/auth/domain"
	"github.com/aussiebroadwan/bartab/internal/auth/store/drivers/sqlite/gen"
)

type clientsRepo struct {
	q *gen.Queries
}

func (r *clientsRepo) GetClientByID(ctx context.Context, id string) (domain.Client, error) {
	row, err := r.q.GetClientByID(ctx, id)
	if err != nil {
		return domain.Client{}, mapNotFound(err)
	}
	return mapClient(row), nil
}

func (r *clientsRepo) ListClients(ctx context.Context) ([]domain.Client, error) {
	rows, err := r.q.ListClients(ctx)
	if err != nil {
		return nil, err
	}

	clients := make([]domain.Client, len(rows))
	for i, row := range rows {
		clients[i] = mapClient(row)
	}
	return clients, nil
}

func (r *clientsRepo) CreateClient(ctx context.Context, c domain.Client) error {
	return r.q.CreateClient(ctx, gen.CreateClientParams{
		ID:         c.ID,
		Name:       c.Name,
		SecretHash: mapStringNull(c.SecretHash),
		Scopes:     strings.Join(c.Scopes, " "),
		Protected:  c.Protected,
	})
}

func (r *clientsRepo) UpdateClientSecretHash(
	ctx context.Context,
	clientID, secretHash string,
) error {
	return r.q.UpdateClientSecretHash(ctx, gen.UpdateClientSecretHashParams{
		SecretHash: mapStringNull(secretHash),
		ID:         clientID,
	})
}

func (r *clientsRepo) UpdateClientScopes(
	ctx context.Context,
	clientID string,
	scopes []string,
) error {
	return r.q.UpdateClientScopes(ctx, gen.UpdateClientScopesParams{
		Scopes: strings.Join(scopes, " "),
		ID:     clientID,
	})
}

func (r *clientsRepo) UpdateClientName(ctx context.Context, clientID, name string) error {
	return r.q.UpdateClientName(ctx, gen.UpdateClientNameParams{
		Name: name,
		ID:   clientID,
	})
}

func (r *clientsRepo) DeleteClient(ctx context.Context, clientID string) error {
	return r.q.DeleteClient(ctx, clientID)
}

func (r *clientsRepo) IsEmpty(ctx context.Context) (bool, error) {
	count, err := r.q.CountClients(ctx)
	if err != nil {
		return false, err
	}
	return count == 0, nil
}
