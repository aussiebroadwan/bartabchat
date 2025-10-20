package service

import (
	"context"

	"github.com/aussiebroadwan/bartab/internal/auth/domain"
	"github.com/aussiebroadwan/bartab/internal/auth/store"
)

type UserService struct {
	Store store.Store
}

// GetUserByID fetches a user by id.
func (s *UserService) GetUserByID(ctx context.Context, userID string) (domain.User, error) {
	return s.Store.Users().GetUserByID(ctx, userID)
}
