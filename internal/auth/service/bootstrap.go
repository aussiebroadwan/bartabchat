package service

import (
	"context"
	"errors"
	"log/slog"

	"github.com/aussiebroadwan/bartab/internal/auth/domain"
	"github.com/aussiebroadwan/bartab/internal/auth/store"
	"github.com/aussiebroadwan/bartab/pkg/cryptox"
	"github.com/aussiebroadwan/bartab/pkg/idx"
	"github.com/aussiebroadwan/bartab/pkg/slogx"
)

var (
	ErrBootstrapAlready              = errors.New("system already bootstrapped")
	ErrBootstrapUnauthorized         = errors.New("unauthorized bootstrap attempt")
	ErrBootstrapFailedToCreateAdmin  = errors.New("failed to create admin user")
	ErrBootstrapFailedToCreateClient = errors.New("failed to create client")
)

type BootstrapService struct {
	Store store.Store
	Token string // Pre-configured bootstrap token
}

func (s *BootstrapService) IsBootstrapped(ctx context.Context) (bool, error) {
	userEmpty, err := s.Store.Users().IsEmpty(ctx)
	if err != nil {
		return false, err
	}
	clientEmpty, err := s.Store.Clients().IsEmpty(ctx)
	if err != nil {
		return false, err
	}
	return !userEmpty && !clientEmpty, nil
}

func (s *BootstrapService) Bootstrap(
	ctx context.Context,
	token string,
	req domain.BootstrapData,
) (string, string, string, error) {
	var err error
	l := slogx.FromContext(ctx)

	// 1. Check if already bootstrapped
	if bootstrapped, _ := s.IsBootstrapped(ctx); bootstrapped {
		l.Warn("attempted bootstrap on already-bootstrapped system")
		return "", "", "", ErrBootstrapAlready
	}

	// 2. Validate provided token
	if token != s.Token {
		l.Warn("unauthorized bootstrap attempt", slog.String("provided_token", token))
		return "", "", "", ErrBootstrapUnauthorized
	}

	// 3. Hash password
	passHash, err := cryptox.HashPassword(req.AdminPassword)
	if err != nil {
		l.Error("failed to hash admin password", slog.Any("error", err))
		return "", "", "", ErrBootstrapFailedToCreateAdmin
	}

	// 4. Generate client secret
	clientSecret, err := cryptox.GenerateToken(cryptox.TokenSize256)
	if err != nil {
		l.Error("failed to generate client secret", slog.Any("error", err))
		return "", "", "", errors.New("failed to generate client secret")
	}

	clientSecretHash, err := cryptox.HashPassword(clientSecret)
	if err != nil {
		l.Error("failed to hash client secret", slog.Any("error", err))
		return "", "", "", errors.New("failed to hash client secret")
	}

	// 5. Create roles, admin user, and client in a transaction
	adminUserID := idx.New().String()
	clientID := idx.New().String()
	err = s.Store.WithTx(ctx, func(tx store.Tx) error {
		// 1. Create roles first (users depend on roles)
		roleIDMap := make(map[string]string) // name to id
		for _, roleDef := range req.Roles {
			roleID := idx.New().String()
			err := tx.Roles().CreateRole(ctx, domain.Role{
				ID:     roleID,
				Name:   roleDef.Name,
				Scopes: roleDef.Scopes,
			})
			if err != nil {
				l.Error("failed to create role",
					slog.String("role_name", roleDef.Name),
					slog.Any("error", err),
				)
				return errors.New("failed to create role")
			}
			roleIDMap[roleDef.Name] = roleID
		}

		// 2. Find admin role (required for bootstrap)
		adminRoleID, ok := roleIDMap["admin"]
		if !ok {
			l.Error("bootstrap requires 'admin' role")
			return errors.New("bootstrap must define 'admin' role")
		}

		// 3. Create admin user
		err = tx.Users().CreateUser(ctx, domain.User{
			ID:            adminUserID,
			Username:      req.AdminUsername,
			PreferredName: req.AdminPreferredName,
			PasswordHash:  passHash,
			RoleID:        adminRoleID,
		})
		if err != nil {
			l.Error("failed to create admin user",
				slog.String("admin_user_id", adminUserID),
				slog.Any("error", err),
			)
			return ErrBootstrapFailedToCreateAdmin
		}

		// 4. Create client (confidential, with secret, protected from deletion)
		err = tx.Clients().CreateClient(ctx, domain.Client{
			ID:         clientID,
			Name:       req.ClientName,
			SecretHash: clientSecretHash, // Confidential client with secret
			Scopes:     req.ClientScopes,
			Protected:  true, // Bootstrap client cannot be deleted
		})
		if err != nil {
			l.Error("failed to create client",
				slog.String("client_id", clientID),
				slog.Any("error", err),
			)
			return ErrBootstrapFailedToCreateClient
		}
		return nil
	})
	if err != nil {
		return "", "", "", err
	}

	l.Info("successfully bootstrapped system",
		slog.String("admin_user_id", adminUserID),
		slog.String("client_id", clientID),
	)
	return adminUserID, clientID, clientSecret, nil
}
