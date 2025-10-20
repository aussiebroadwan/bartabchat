package service

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/aussiebroadwan/bartab/internal/auth/domain"
	"github.com/aussiebroadwan/bartab/internal/auth/store"
	"github.com/aussiebroadwan/bartab/pkg/authsdk"
	"github.com/aussiebroadwan/bartab/pkg/cryptox"
	"github.com/aussiebroadwan/bartab/pkg/idx"
	"github.com/aussiebroadwan/bartab/pkg/jwtx"
	"github.com/aussiebroadwan/bartab/pkg/slogx"
	"github.com/pquerna/otp/totp"
)

const (
	// MaxMFAAttempts is the maximum number of failed MFA attempts allowed per session
	MaxMFAAttempts = 5
)

var (
	ErrInvalidCredentials = errors.New("invalid_credentials")
	ErrInvalidClient      = errors.New("invalid_client")
	ErrInvalidScope       = errors.New("invalid_scope")
	ErrInvalidRefresh     = errors.New("invalid_refresh_token")
	ErrInvalidGrant       = errors.New("invalid_grant")
	ErrTooManyAttempts    = errors.New("too_many_attempts")
)

// MFARequiredError is an alias to the SDK's MFARequiredError for consistency.
// Use authsdk.MFARequiredError directly in new code.
type MFARequiredError = authsdk.MFARequiredError

type TokenService struct {
	KeyManager *jwtx.KeyManager // Changed from Signer to support multi-key rotation
	Store      store.Store
	Issuer     string
	AccessTTL  time.Duration
	RefreshTTL time.Duration
}

// ExchangeAuthorizationCode implements the OAuth2 authorization_code grant.
//
// It validates the client authentication (for confidential clients),
// verifies the authorization code, enforces PKCE, and issues new tokens.
func (s *TokenService) ExchangeAuthorizationCode(
	ctx context.Context,
	clientID, clientSecret, code, redirectURI, codeVerifier string,
) (*domain.TokenPair, error) {
	now := time.Now()
	l := slogx.FromContext(ctx)

	client, err := s.Store.Clients().GetClientByID(ctx, clientID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, ErrInvalidClient
		}
		return nil, err
	}

	// Confidential clients must authenticate
	if client.SecretHash != "" {
		if clientSecret == "" || cryptox.VerifyPassword(clientSecret, client.SecretHash) != nil {
			l.Info("authorization_code grant client authentication failed", slog.String("client_id", clientID))
			return nil, ErrInvalidClient
		}
	}

	code = strings.TrimSpace(code)
	redirectURI = strings.TrimSpace(redirectURI)
	codeVerifier = strings.TrimSpace(codeVerifier)
	if code == "" || redirectURI == "" {
		return nil, ErrInvalidGrant
	}

	codeHash := cryptox.FingerprintToken(code)

	var result *domain.TokenPair

	err = s.Store.WithTx(ctx, func(tx store.Tx) error {
		authCode, err := tx.AuthorizationCodes().GetAuthorizationCodeByHash(ctx, codeHash)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return ErrInvalidGrant
			}
			return err
		}

		if authCode.ClientID != client.ID {
			return ErrInvalidClient
		}
		if authCode.RedirectURI != redirectURI {
			return ErrInvalidGrant
		}
		if authCode.UsedAt != nil || now.After(authCode.ExpiresAt) {
			return ErrInvalidGrant
		}
		if !verifyCodeVerifier(authCode.CodeChallenge, authCode.CodeChallengeMethod, codeVerifier) {
			return ErrInvalidGrant
		}

		user, err := tx.Users().GetUserByID(ctx, authCode.UserID)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return ErrInvalidGrant
			}
			return err
		}

		role, err := tx.Roles().GetRoleByID(ctx, user.RoleID)
		if err != nil {
			return err
		}

		effective := intersectThreeWay(authCode.Scopes, client.Scopes, role.Scopes)
		if len(effective) == 0 {
			return ErrInvalidScope
		}

		sessionID := authCode.SessionID
		if sessionID == "" {
			sessionID = idx.New().String()
		}

		amr := dedupe(authCode.AMR)
		if len(amr) == 0 {
			amr = []string{jwtx.AMRPassword}
		}

		accessToken, err := s.signAccess(user, client.ID, sessionID, effective, amr, now)
		if err != nil {
			return err
		}

		refreshOpaque, err := cryptox.GenerateToken(cryptox.TokenSize256)
		if err != nil {
			return err
		}
		refreshFP := cryptox.FingerprintToken(refreshOpaque)

		refresh := domain.RefreshToken{
			ID:        idx.New().String(),
			UserID:    user.ID,
			ClientID:  client.ID,
			TokenHash: refreshFP,
			SessionID: sessionID,
			Scopes:    effective,
			AMR:       amr,
			ExpiresAt: now.Add(s.RefreshTTL),
			Revoked:   false,
		}

		if err := tx.AuthorizationCodes().MarkAuthorizationCodeUsed(ctx, authCode.ID); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return ErrInvalidGrant
			}
			return err
		}

		if err := tx.RefreshTokens().CreateRefreshToken(ctx, refresh); err != nil {
			return err
		}

		result = &domain.TokenPair{
			AccessToken:  accessToken,
			RefreshToken: refreshOpaque,
			ExpiresIn:    s.AccessTTL,
			Scope:        strings.Join(effective, " "),
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return result, nil
}

// ExchangeMFAOTP handles the MFA OTP grant type (mfa_otp).
// It verifies the MFA challenge and issues tokens if successful.
// The MFA session has a maximum of 5 attempts to prevent brute force attacks.
func (s *TokenService) ExchangeMFAOTP(
	ctx context.Context,
	mfaToken, method, otpCode string,
) (*domain.TokenPair, error) {
	now := time.Now()
	l := slogx.FromContext(ctx)

	// 1. Retrieve MFA session
	session, err := s.Store.MFASessions().GetMFASession(ctx, mfaToken)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, ErrInvalidGrant
		}
		return nil, err
	}

	// 2. Check if max attempts exceeded
	if session.Attempts >= MaxMFAAttempts {
		// Delete the session to prevent further attempts
		_ = s.Store.MFASessions().DeleteMFASession(ctx, mfaToken)
		l.Warn("MFA session exceeded max attempts", "mfa_token", mfaToken, "attempts", session.Attempts)
		return nil, ErrTooManyAttempts
	}

	// 3. Load user to get MFA secret
	u, err := s.Store.Users().GetUserByID(ctx, session.UserID)
	if err != nil {
		l.Error("failed to get user",
			slog.Any("error", err),
			slog.String("user_id", session.UserID),
		)
		return nil, err
	}

	// 4. Verify OTP based on method
	var mfaMethod string
	var validationErr error

	switch method {
	case "totp":
		// Verify TOTP code
		if u.MFASecret == nil || *u.MFASecret == "" {
			validationErr = errors.New("MFA secret not found")
		} else if !totp.Validate(otpCode, *u.MFASecret) {
			validationErr = errors.New("invalid TOTP code")
		} else {
			mfaMethod = jwtx.AMRMFA
		}

	case "backup_codes":
		// Verify backup code
		codeHash := cryptox.FingerprintToken(otpCode)
		valid, err := s.Store.BackupCodes().VerifyBackupCode(ctx, u.ID, codeHash)
		if err != nil {
			l.Error("failed to verify backup code", "error", err)
			return nil, err
		}
		if !valid {
			validationErr = errors.New("invalid backup code")
		} else {
			// Delete the used backup code
			if err := s.Store.BackupCodes().DeleteBackupCode(ctx, u.ID, codeHash); err != nil {
				l.Error("failed to delete backup code", "error", err)
				return nil, err
			}
			mfaMethod = jwtx.AMRMFA
		}

	default:
		return nil, ErrInvalidGrant
	}

	// 5. If validation failed, increment attempts and return error
	if validationErr != nil {
		updatedSession, err := s.Store.MFASessions().IncrementMFASessionAttempts(ctx, mfaToken)
		if err != nil {
			l.Error("failed to increment MFA attempts", "error", err)
			// Still return the validation error even if increment fails
			return nil, ErrInvalidGrant
		}
		l.Warn("MFA validation failed", "mfa_token", mfaToken, "attempts", updatedSession.Attempts, "method", method)
		return nil, ErrInvalidGrant
	}

	// 6. Update AMR to include MFA method
	amr := append(session.AMR, mfaMethod)

	// 7. Sign access token
	accessToken, err := s.signAccess(u, session.ClientID, session.SessionID, session.Scopes, amr, now)
	if err != nil {
		return nil, err
	}

	// 8. Create refresh token
	refreshOpaque, err := cryptox.GenerateToken(cryptox.TokenSize256)
	if err != nil {
		return nil, err
	}
	refreshFP := cryptox.FingerprintToken(refreshOpaque)

	rt := domain.RefreshToken{
		ID:        idx.New().String(),
		UserID:    u.ID,
		ClientID:  session.ClientID,
		TokenHash: refreshFP,
		SessionID: session.SessionID,
		Scopes:    session.Scopes,
		AMR:       amr, // Include MFA method in AMR
		ExpiresAt: now.Add(s.RefreshTTL),
		Revoked:   false,
	}

	// 9. Store refresh token and delete MFA session atomically
	if err := s.Store.WithTx(ctx, func(tx store.Tx) error {
		if err := tx.RefreshTokens().CreateRefreshToken(ctx, rt); err != nil {
			return err
		}
		return tx.MFASessions().DeleteMFASession(ctx, mfaToken)
	}); err != nil {
		return nil, err
	}

	// 10. Return token pair
	return &domain.TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshOpaque,
		ExpiresIn:    s.AccessTTL,
		Scope:        strings.Join(session.Scopes, " "),
	}, nil
}

// ExchangeRefreshToken implements the OAuth2 refresh_token grant.
//
// It validates the provided refresh token (by fingerprint lookup + expiry/revocation check),
// optionally allows scope narrowing and widening, then issues a new access token.
func (s *TokenService) ExchangeRefreshToken(
	ctx context.Context,
	clientID string,
	refreshOpaque string,
	requestedScopes []string, // Empty means reuse original scopes
) (*domain.TokenPair, error) {
	now := time.Now()

	// 1. Lookup the persisted refresh row by token fingerprint
	fp := cryptox.FingerprintToken(refreshOpaque)
	rt, err := s.Store.RefreshTokens().GetRefreshTokenByHash(ctx, fp)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, ErrInvalidRefresh
		}
		return nil, err
	}

	// 2. Validate token is not expired or revoked. The SQL query should
	// ideally filter these out, but we double-check here for defense in depth.
	if rt.Revoked {
		return nil, ErrInvalidRefresh
	}
	if now.After(rt.ExpiresAt) {
		return nil, ErrInvalidRefresh
	}

	// 3. Ensure it belongs to the client using it
	if rt.ClientID != clientID {
		return nil, ErrInvalidClient
	}

	// 4. Load user, role, and client to compute effective scopes
	u, err := s.Store.Users().GetUserByID(ctx, rt.UserID)
	if err != nil {
		return nil, err
	}

	// Load user's role
	role, err := s.Store.Roles().GetRoleByID(ctx, u.RoleID)
	if err != nil {
		return nil, err
	}

	c, err := s.Store.Clients().GetClientByID(ctx, clientID)
	if err != nil {
		return nil, err
	}

	// 5. Determine base scopes: allow both narrowing AND expansion.
	base := rt.Scopes
	if len(requestedScopes) > 0 {
		base = requestedScopes
	}

	// 6. Three-way intersection: requested & client & role
	// This ensures users can only refresh tokens with scopes their role allows
	effective := intersectThreeWay(base, c.Scopes, role.Scopes)
	if len(effective) == 0 {
		return nil, ErrInvalidScope
	}

	// 7. Preserve AMR history: append "refresh" to existing authentication methods
	rt.AMR = append(rt.AMR, jwtx.AMRRefresh)
	amr := dedupe(rt.AMR) // Remove duplicates to keep AMR list clean

	// 8. Issue new access token with preserved AMR history and reused session ID
	accessToken, err := s.signAccess(u, clientID, rt.SessionID, effective, amr, now)
	if err != nil {
		return nil, err
	}

	// 9. Implement refresh token rotation for security:
	// Generate new refresh token, revoke old one in a single transaction
	newRefreshOpaque, err := cryptox.GenerateToken(cryptox.TokenSize256)
	if err != nil {
		return nil, err
	}
	newRefreshFP := cryptox.FingerprintToken(newRefreshOpaque)

	newRT := domain.RefreshToken{
		ID:        idx.New().String(),
		UserID:    u.ID,
		ClientID:  c.ID,
		TokenHash: newRefreshFP,
		SessionID: rt.SessionID, // Preserve session ID across refresh
		Scopes:    effective,
		AMR:       amr, // Preserve AMR history in the new refresh token
		ExpiresAt: now.Add(s.RefreshTTL),
		Revoked:   false,
	}

	// Atomically: revoke old token and create new one
	if err := s.Store.WithTx(ctx, func(tx store.Tx) error {
		if err := tx.RefreshTokens().RevokeRefreshToken(ctx, fp); err != nil {
			return err
		}
		return tx.RefreshTokens().CreateRefreshToken(ctx, newRT)
	}); err != nil {
		return nil, err
	}

	// 9. Return new pair (new refresh token)
	return &domain.TokenPair{
		AccessToken:  accessToken,
		RefreshToken: newRefreshOpaque, // return new refresh token (rotated)
		ExpiresIn:    s.AccessTTL,
		Scope:        strings.Join(effective, " "),
	}, nil
}

// ExchangeClientCredentials implements the OAuth2 client_credentials grant.
//
// This grant is used for machine-to-machine (M2M) authentication where a client
// authenticates as itself (not on behalf of a user). The client must be confidential
// (have a secret_hash) to use this grant.
//
// Key differences from other grants:
// - No user context (client IS the subject)
// - No refresh token issued (client can always re-authenticate)
// - Scopes limited to client's allowed scopes only (no role intersection)
// - AMR is set to "client"
func (s *TokenService) ExchangeClientCredentials(
	ctx context.Context,
	clientID, clientSecret string,
	requestedScopes []string,
) (*domain.TokenPair, error) {
	now := time.Now()
	l := slogx.FromContext(ctx)

	// 1. Load client
	c, err := s.Store.Clients().GetClientByID(ctx, clientID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, ErrInvalidClient
		}
		return nil, err
	}

	// 2. Ensure client has a secret (must be confidential for client_credentials)
	if c.SecretHash == "" {
		l.Warn("client_credentials grant attempted with public client", "client_id", clientID)
		return nil, ErrInvalidClient
	}

	// 3. Verify client secret
	if err := cryptox.VerifyPassword(clientSecret, c.SecretHash); err != nil {
		l.Info("client secret verification failed", "client_id", clientID)
		return nil, ErrInvalidClient
	}

	// 4. Compute effective scopes: only client scopes apply (no user/role)
	// If no scopes requested, grant all client scopes
	effective := requestedScopes
	if len(effective) == 0 {
		effective = c.Scopes
	} else {
		// Intersect requested with client's allowed scopes
		effective = intersectScopes(requestedScopes, c.Scopes)
	}

	if len(effective) == 0 {
		return nil, ErrInvalidScope
	}

	// 5. Generate session ID (optional for client_credentials, but useful for tracking)
	sessionID := idx.New().String()

	// 6. Build and sign access token
	// For client_credentials, the client is the subject (not a user)
	claims := jwtx.NewAccessClaims(
		c.ID,                     // subject = client_id
		sessionID,                // session ID
		effective,                // scopes
		[]string{jwtx.AMRClient}, // authentication method: client
		s.AccessTTL,              // token lifetime
		s.Issuer,                 // issuer
		[]string{c.ID},           // audience = client_id
		c.Name,                   // username = client name (for visibility)
		c.Name,                   // preferred_name = client name
		now,                      // current time
	)

	// Use GetSigner() to distribute signing across multiple keys
	signer := s.KeyManager.GetSigner()
	accessToken, err := signer.Sign(claims)
	if err != nil {
		l.Error("failed to sign access token", "error", err)
		return nil, err
	}

	// 7. Return token pair WITHOUT refresh token
	// Client credentials grant doesn't issue refresh tokens since the client
	// can always re-authenticate with its credentials
	return &domain.TokenPair{
		AccessToken:  accessToken,
		RefreshToken: "", // no refresh token for client_credentials
		ExpiresIn:    s.AccessTTL,
		Scope:        strings.Join(effective, " "),
	}, nil
}

// RevokeRefreshToken revokes a single refresh token (by its opaque value).
func (s *TokenService) RevokeRefreshToken(ctx context.Context, refreshOpaque string) error {
	fp := cryptox.FingerprintToken(refreshOpaque)
	return s.Store.RefreshTokens().RevokeRefreshToken(ctx, fp)
}

func (s *TokenService) signAccess(
	u domain.User,
	clientID string,
	sessionID string,
	scopes []string,
	amr []string,
	now time.Time,
) (string, error) {
	claims := jwtx.NewAccessClaims(
		u.ID,               // subject
		sessionID,          // session ID
		scopes,             // scopes
		amr,                // authentication methods
		s.AccessTTL,        // token lifetime
		s.Issuer,           // issuer
		[]string{clientID}, // audience
		u.Username,         // username
		u.PreferredName,    // preferred name
		now,                // current time
	)
	// Use GetSigner() to distribute signing across multiple keys
	signer := s.KeyManager.GetSigner()
	return signer.Sign(claims)
}

// intersectThreeWay performs a three-way intersection of scopes.
// This is the core security mechanism that prevents privilege escalation:
// - requested: What the user is asking for
// - clientScopes: What the client is authorized to grant
// - roleScopes: What the user's role allows them to have.
func intersectThreeWay(requested, clientScopes, roleScopes []string) []string {
	// First intersect requested with client scopes
	step1 := intersectScopes(requested, clientScopes)
	// Then intersect result with role scopes
	return intersectScopes(step1, roleScopes)
}

func intersectScopes(a, b []string) []string {
	set := map[string]struct{}{}
	for _, s := range b {
		set[s] = struct{}{}
	}
	var out []string
	for _, s := range a {
		if _, ok := set[s]; ok {
			out = append(out, s)
		}
	}
	return dedupe(out)
}

func dedupe(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

func verifyCodeVerifier(challenge, method, verifier string) bool {
	challenge = strings.TrimSpace(challenge)
	if challenge == "" {
		// No PKCE challenge stored; accept regardless of verifier.
		return true
	}

	verifier = strings.TrimSpace(verifier)
	if verifier == "" {
		return false
	}

	method = strings.TrimSpace(method)
	switch {
	case method == "" || strings.EqualFold(method, "plain"):
		return subtle.ConstantTimeCompare([]byte(challenge), []byte(verifier)) == 1
	case strings.EqualFold(method, "S256"):
		sum := sha256.Sum256([]byte(verifier))
		expected := base64.RawURLEncoding.EncodeToString(sum[:])
		return subtle.ConstantTimeCompare([]byte(challenge), []byte(expected)) == 1
	default:
		return false
	}
}
