package service

import (
	"context"
	"errors"

	"github.com/aussiebroadwan/bartab/internal/auth/domain"
	"github.com/aussiebroadwan/bartab/internal/auth/store"
	"github.com/aussiebroadwan/bartab/pkg/cryptox"
	"github.com/aussiebroadwan/bartab/pkg/idx"
	"github.com/aussiebroadwan/bartab/pkg/slogx"
)

var (
	ErrClientNotFound  = errors.New("client not found")
	ErrClientProtected = errors.New("client is protected and cannot be deleted")
)

type ClientService struct {
	Store store.Store
}

// CreateClient creates a new OAuth2 client.
// If confidential is true, auto-generates a secure secret and returns it (shown only once).
// Returns the client ID and the plaintext secret (if confidential) which should be shown once to the user.
func (s *ClientService) CreateClient(
	ctx context.Context,
	name string,
	confidential bool,
	scopes []string,
) (clientID string, plaintextSecret string, err error) {
	l := slogx.FromContext(ctx)

	// Generate and hash secret if confidential client
	var secretHash string
	if confidential {
		// Generate a secure 256-bit secret (32 bytes = 64 hex chars)
		secret, err := cryptox.GenerateToken(cryptox.TokenSize256)
		if err != nil {
			l.Error("failed to generate client secret", "error", err)
			return "", "", err
		}
		plaintextSecret = secret

		secretHash, err = cryptox.HashPassword(secret)
		if err != nil {
			l.Error("failed to hash client secret", "error", err)
			return "", "", err
		}
	}

	// Generate client ID
	clientID = idx.New().String()

	// Create client
	err = s.Store.Clients().CreateClient(ctx, domain.Client{
		ID:         clientID,
		Name:       name,
		SecretHash: secretHash,
		Scopes:     scopes,
		Protected:  false, // New clients are not protected
	})
	if err != nil {
		l.Error("failed to create client", "error", err)
		return "", "", err
	}

	l.Info("client created successfully", "client_id", clientID, "name", name, "has_secret", confidential)
	return clientID, plaintextSecret, nil
}

// ListClients returns all OAuth2 clients.
func (s *ClientService) ListClients(ctx context.Context) ([]domain.Client, error) {
	return s.Store.Clients().ListClients(ctx)
}

// DeleteClient deletes an OAuth2 client by ID.
// Returns ErrClientProtected if the client is protected (e.g., bootstrap client).
func (s *ClientService) DeleteClient(ctx context.Context, clientID string) error {
	l := slogx.FromContext(ctx)

	// Load client to check if it's protected
	client, err := s.Store.Clients().GetClientByID(ctx, clientID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return ErrClientNotFound
		}
		return err
	}

	// Check if client is protected
	if client.Protected {
		l.Warn("attempted to delete protected client", "client_id", clientID)
		return ErrClientProtected
	}

	// Delete the client
	err = s.Store.Clients().DeleteClient(ctx, clientID)
	if err != nil {
		l.Error("failed to delete client", "error", err, "client_id", clientID)
		return err
	}

	l.Info("client deleted successfully", "client_id", clientID)
	return nil
}
