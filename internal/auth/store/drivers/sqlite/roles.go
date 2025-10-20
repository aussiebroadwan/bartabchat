package sqlite

import (
	"context"
	"strings"

	"github.com/aussiebroadwan/bartab/internal/auth/domain"
	"github.com/aussiebroadwan/bartab/internal/auth/store/drivers/sqlite/gen"
)

type rolesRepo struct {
	q *gen.Queries
}

func (r *rolesRepo) GetRoleByID(ctx context.Context, id string) (domain.Role, error) {
	row, err := r.q.GetRoleByID(ctx, id)
	if err != nil {
		return domain.Role{}, mapNotFound(err)
	}
	return mapRole(row), nil
}

func (r *rolesRepo) GetRoleByName(ctx context.Context, name string) (domain.Role, error) {
	row, err := r.q.GetRoleByName(ctx, name)
	if err != nil {
		return domain.Role{}, mapNotFound(err)
	}
	return mapRole(row), nil
}

func (r *rolesRepo) ListAll(ctx context.Context) ([]domain.Role, error) {
	rows, err := r.q.ListAllRoles(ctx)
	if err != nil {
		return nil, err
	}

	roles := make([]domain.Role, len(rows))
	for i, row := range rows {
		roles[i] = mapRole(row)
	}
	return roles, nil
}

func (r *rolesRepo) CreateRole(ctx context.Context, role domain.Role) error {
	return r.q.CreateRole(ctx, gen.CreateRoleParams{
		ID:     role.ID,
		Name:   role.Name,
		Scopes: strings.Join(role.Scopes, " "),
	})
}

func (r *rolesRepo) UpdateRoleScopes(ctx context.Context, roleID string, scopes []string) error {
	return r.q.UpdateRoleScopes(ctx, gen.UpdateRoleScopesParams{
		Scopes: strings.Join(scopes, " "),
		ID:     roleID,
	})
}

func (r *rolesRepo) DeleteRole(ctx context.Context, roleID string) error {
	return r.q.DeleteRole(ctx, roleID)
}

func (r *rolesRepo) IsEmpty(ctx context.Context) (bool, error) {
	count, err := r.q.CountRoles(ctx)
	if err != nil {
		return false, err
	}
	return count == 0, nil
}
