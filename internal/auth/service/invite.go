package service

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/aussiebroadwan/bartab/internal/auth/domain"
	"github.com/aussiebroadwan/bartab/internal/auth/store"
	"github.com/aussiebroadwan/bartab/pkg/cryptox"
	"github.com/aussiebroadwan/bartab/pkg/idx"
	"github.com/aussiebroadwan/bartab/pkg/slogx"
)

var (
	ErrInvalidInviteRequest        = errors.New("invalid invite request")
	ErrAdminInviteCannotBeReusable = errors.New("admin invites cannot be reusable")
	ErrInvalidRole                 = errors.New("invalid role")
	ErrInviteNotFound              = errors.New("invite not found or expired")
	ErrInviteAlreadyUsed           = errors.New("invite has already been used")
	ErrUsernameAlreadyTaken        = errors.New("username already taken")
	ErrInviteClientMismatch        = errors.New("invite was issued for a different client")
)

type InviteService struct {
	Store store.Store
}

// MintInvite creates a new invite token for a client.
func (s *InviteService) MintInvite(
	ctx context.Context,
	clientID string,
	roleID string,
	expiresAt time.Time,
	reusable bool,
	createdBy string,
) (string, error) {
	log := slogx.FromContext(ctx)

	// 1. Validate role exists
	role, err := s.Store.Roles().GetRoleByID(ctx, roleID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			log.Warn("attempted to create invite with invalid role",
				slog.String("role_id", roleID),
			)
			return "", ErrInvalidRole
		}
		log.Error("failed to fetch role", slog.Any("error", err))
		return "", err
	}

	// 2. Validate business rules: Admin role invites cannot be reusable.
	// This prevents privilege escalation via shared invite tokens.
	if role.Name == "admin" && reusable {
		log.Warn("attempted to create reusable admin invite",
			slog.String("client_id", clientID),
			slog.String("created_by", createdBy),
			slog.String("role", role.Name),
		)
		return "", ErrAdminInviteCannotBeReusable
	}

	// 3. Validate expiry is in the future.
	if expiresAt.Before(time.Now()) {
		log.Warn("attempted to create invite with past expiry",
			slog.String("client_id", clientID),
			slog.Time("expires_at", expiresAt),
		)
		return "", ErrInvalidInviteRequest
	}

	// 4. Validate client exists.
	_, err = s.Store.Clients().GetClientByID(ctx, clientID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			log.Warn("attempted to create invite for non-existent client",
				slog.String("client_id", clientID),
			)
			return "", ErrInvalidClient
		}
		log.Error("failed to fetch client", slog.Any("error", err))
		return "", err
	}

	// 5. Generate random token.
	token, err := cryptox.GenerateToken(cryptox.TokenSize256)
	if err != nil {
		log.Error("failed to generate invite token", slog.Any("error", err))
		return "", err
	}

	// 6. Fingerprint and store the invite.
	fingerprint := cryptox.FingerprintToken(token)

	invite := domain.Invite{
		ID:        idx.New().String(),
		TokenHash: fingerprint,
		ClientID:  clientID,
		CreatedBy: createdBy,
		RoleID:    roleID,
		ExpiresAt: expiresAt,
		Reusable:  reusable,
		Used:      false,
		UsedBy:    "",
	}

	// 7. Store invite in a transaction.
	err = s.Store.WithTx(ctx, func(tx store.Tx) error {
		if err := s.Store.Invites().CreateInvite(ctx, invite); err != nil {
			log.Error("failed to create invite",
				slog.String("invite_id", invite.ID),
				slog.Any("error", err),
			)
			return err
		}
		return nil
	})
	if err != nil {
		return "", err
	}

	log.Debug("invite created",
		slog.String("invite_id", invite.ID),
		slog.String("client_id", clientID),
		slog.String("role_id", roleID),
		slog.String("role_name", role.Name),
		slog.Bool("reusable", reusable),
		slog.Time("expires_at", expiresAt),
	)

	// 8. Return the raw token (not the fingerprint).
	return token, nil
}

// RedeemInvite validates an invite token and creates a new user account.
// It performs the following steps:
// 1. Validates input parameters
// 2. Fingerprints and looks up the invite
// 3. Validates the invite is for the correct client
// 4. Checks if invite is already used (only matters for non-reusable invites)
// 5. Verifies username is available
// 6. Creates user with hashed password and role from invite
// 7. Marks invite as used if not reusable (atomically in a transaction)
func (s *InviteService) RedeemInvite(
	ctx context.Context,
	inviteToken string,
	username string,
	password string,
	clientID string,
) (domain.User, error) {
	log := slogx.FromContext(ctx)

	// 1. Validate input
	if inviteToken == "" || username == "" || password == "" || clientID == "" {
		log.Warn("invite redemption missing required fields")
		return domain.User{}, ErrInvalidInviteRequest
	}

	// 2. Fingerprint the invite token and look it up
	fingerprint := cryptox.FingerprintToken(inviteToken)
	invite, err := s.Store.Invites().GetActiveInviteByTokenHash(ctx, fingerprint)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			log.Warn("invite redemption attempted with invalid or expired token",
				slog.String("client_id", clientID),
			)
			return domain.User{}, ErrInviteNotFound
		}
		log.Error("failed to fetch invite", slog.Any("error", err))
		return domain.User{}, err
	}

	// 3. Verify the invite is for the correct client
	if invite.ClientID != clientID {
		log.Warn("invite redemption attempted for wrong client",
			slog.String("invite_client_id", invite.ClientID),
			slog.String("provided_client_id", clientID),
			slog.String("invite_id", invite.ID),
		)
		return domain.User{}, ErrInviteClientMismatch
	}

	// 4. Check if invite is already used (only matters if not reusable)
	if !invite.Reusable && invite.Used {
		log.Warn("invite redemption attempted with already-used non-reusable invite",
			slog.String("invite_id", invite.ID),
			slog.String("used_by", invite.UsedBy),
		)
		return domain.User{}, ErrInviteAlreadyUsed
	}

	// 5. Verify username is available
	_, err = s.Store.Users().GetUserByUsername(ctx, username)
	if err == nil {
		log.Warn("invite redemption attempted with already-taken username",
			slog.String("username", username),
			slog.String("invite_id", invite.ID),
		)
		return domain.User{}, ErrUsernameAlreadyTaken
	}
	if !errors.Is(err, store.ErrNotFound) {
		log.Error("failed to check username availability", slog.Any("error", err))
		return domain.User{}, err
	}

	// 6. Hash the password using Argon2id
	passwordHash, err := cryptox.HashPassword(password)
	if err != nil {
		log.Error("failed to hash password", slog.Any("error", err))
		return domain.User{}, err
	}

	// 7. Create the user and mark invite as used if not reusable (atomically)
	var newUser domain.User
	err = s.Store.WithTx(ctx, func(tx store.Tx) error {
		// Create user with role from invite
		newUser = domain.User{
			ID:            idx.New().String(),
			Username:      username,
			PreferredName: username, // Default to username
			PasswordHash:  passwordHash,
			RoleID:        invite.RoleID,
		}

		if err := s.Store.Users().CreateUser(ctx, newUser); err != nil {
			log.Error("failed to create user",
				slog.String("username", username),
				slog.Any("error", err),
			)
			return err
		}

		// Mark invite as used only if it's not reusable
		if !invite.Reusable {
			if err := s.Store.Invites().MarkInviteUsed(ctx, invite.ID, newUser.ID); err != nil {
				log.Error("failed to mark invite as used",
					slog.String("invite_id", invite.ID),
					slog.String("user_id", newUser.ID),
					slog.Any("error", err),
				)
				return err
			}
		}

		return nil
	})
	if err != nil {
		return domain.User{}, err
	}

	log.Info("user registered via invite",
		slog.String("user_id", newUser.ID),
		slog.String("username", newUser.Username),
		slog.String("invite_id", invite.ID),
		slog.String("role_id", invite.RoleID),
		slog.String("client_id", clientID),
	)

	return newUser, nil
}
