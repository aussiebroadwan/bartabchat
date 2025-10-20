package service

import (
	"context"

	"github.com/aussiebroadwan/bartab/internal/auth/domain"
	"github.com/aussiebroadwan/bartab/internal/auth/store"
)

type RolesService struct {
	Store store.Store
}

// GetRoleByID fetches a role by its ID.
func (s *RolesService) GetRoleByID(ctx context.Context, roleID string) (domain.Role, error) {
	return s.Store.Roles().GetRoleByID(ctx, roleID)
}

// ListAll returns all roles in the system.
func (s *RolesService) ListAll(ctx context.Context) ([]domain.Role, error) {
	return s.Store.Roles().ListAll(ctx)
}
