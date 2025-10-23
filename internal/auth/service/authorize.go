package service

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/aussiebroadwan/bartab/internal/auth/domain"
	"github.com/aussiebroadwan/bartab/internal/auth/store"
	"github.com/aussiebroadwan/bartab/pkg/cryptox"
	"github.com/aussiebroadwan/bartab/pkg/idx"
	"github.com/aussiebroadwan/bartab/pkg/jwtx"
	"github.com/aussiebroadwan/bartab/pkg/slogx"
	"github.com/pquerna/otp/totp"
)

var (
	// Authorization-specific errors that follow the same pattern as TokenService
	ErrLoginRequired      = errors.New("login_required")
	ErrInvalidRequest     = errors.New("invalid_request")
	ErrInvalidRedirectURI = errors.New("redirect_uri_mismatch") // New error type for OAuth2 redirect_uri_mismatch
	ErrInvalidClient      = errors.New("invalid_client")
	ErrInvalidScope       = errors.New("invalid_scope")
	ErrInvalidCredentials = errors.New("invalid_credentials")
	ErrInvalidGrant       = errors.New("invalid_grant")
	ErrTooManyAttempts    = errors.New("too_many_attempts") // Used in MFA flow

	// Internal errors
	errInvalidMFACode = errors.New("invalid_mfa_code")
	mfaMethods        = []string{"totp", "backup_codes"}
	MaxMFAAttempts    = 5 // Maximum attempts for MFA verification
)

// MFARequiredError is returned when MFA is required for authentication.
type MFARequiredError struct {
	MFAToken string
	Methods  []string
}

func (e *MFARequiredError) Error() string {
	return "mfa_required"
}

// AuthorizeService encapsulates the OAuth2 authorization-code issuance flow.
type AuthorizeService struct {
	Store   store.Store
	CodeTTL time.Duration
}

// AuthorizeRequest captures the validated inputs required to issue an authorization code.
type AuthorizeRequest struct {
	ResponseType        string
	ClientID            string
	RedirectURI         string // This is the URI from the request, which needs validation
	Scope               []string
	State               string
	CodeChallenge       string
	CodeChallengeMethod string

	// Username/password pair for interactive login (if no existing session).
	Username string
	Password string

	// Existing authenticated session context (e.g., from a cookie/session store).
	Session *SessionContext

	// Fields used when completing an MFA challenge.
	MFAToken  string
	MFAMethod string
	MFACode   string
}

// SessionContext describes an already authenticated user session.
type SessionContext struct {
	UserID    string
	SessionID string
	AMR       []string
	Scopes    []string
}

// AuthorizeCodeResponse contains the authorization code and redirect information.
// This is returned on successful authorization and should be used to build the redirect.
type AuthorizeCodeResponse struct {
	Code        string
	RedirectURI string
	State       string
}

// IssueAuthorizationCode implements the OAuth2 authorization code flow per RFC 6749 section 4.1.
//
// This method validates the authorization request, enforces security requirements (PKCE, scopes),
// handles user authentication, and issues a short-lived authorization code that can be exchanged
// for access and refresh tokens via the token endpoint.
//
// Authentication Flows:
//
//  1. Existing Session: If req.Session is provided (from cookie/bearer token), the user is already
//     authenticated. The method validates scopes against the user's role and issues a code.
//
//  2. Username/Password: If req.Username and req.Password are provided, the method authenticates
//     the user. If MFA is enabled for the user, returns *MFARequiredError. Otherwise, issues a code.
//
//  3. MFA Completion: If req.MFAToken is provided (from a previous MFA challenge), validates the
//     MFA code (TOTP or backup code) and issues a code.
//
// Security Requirements:
//
//   - PKCE: Public clients (no secret) MUST include code_challenge. Confidential clients may omit it.
//     Defaults to S256 method if code_challenge_method is omitted.
//
//   - Scopes: The granted scopes are the intersection of requested scopes, client scopes, and user
//     role scopes. This prevents privilege escalation.
//
//   - Code TTL: Authorization codes expire after CodeTTL (default: 5 minutes) and are single-use.
//
// Returns:
//   - (*AuthorizeCodeResponse, nil) on success, containing the authorization code, redirect_uri, and state
//   - (nil, *MFARequiredError) when MFA verification is required (status 409, includes mfa_token and methods)
//   - (nil, ErrInvalidClient) when client_id is invalid or misconfigured
//   - (nil, ErrInvalidRequest) when required parameters are missing or PKCE validation fails
//   - (nil, ErrInvalidScope) when no scopes can be granted
//   - (nil, ErrLoginRequired) when authentication is required (no session, no credentials)
//   - (nil, ErrInvalidCredentials) when username/password is incorrect
//   - (nil, ErrInvalidGrant) when MFA token is invalid or session is invalid
//   - (nil, ErrInvalidRedirectURI) when the provided redirect_uri does not match the client's registered uri
//
// Example usage (via HTTP handler):
//
//	resp, err := svc.IssueAuthorizationCode(ctx, AuthorizeRequest{
//	    ResponseType:        "code",
//	    ClientID:            "client-123",
//	    RedirectURI:         "https://app.example.com/callback",
//	    Scope:               []string{"profile:read"},
//	    CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
//	    CodeChallengeMethod: "S256",
//	    Username:            "alice",
//	    Password:            "secret",
//	})
func (s *AuthorizeService) IssueAuthorizationCode(ctx context.Context, req AuthorizeRequest) (*AuthorizeCodeResponse, error) {
	log := slogx.FromContext(ctx)

	if !strings.EqualFold(strings.TrimSpace(req.ResponseType), "code") {
		return nil, ErrInvalidRequest
	}
	if strings.TrimSpace(req.ClientID) == "" || strings.TrimSpace(req.RedirectURI) == "" {
		return nil, ErrInvalidRequest
	}

	// Fetch client configuration.
	client, err := s.Store.Clients().GetClientByID(ctx, req.ClientID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, ErrInvalidClient
		}
		return nil, err
	}

	// Validate req.RedirectURI against the client's registered redirect_uri(s).
	// Assumption: domain.Client has a RedirectURI string field, or a method to get the primary one.
	// If a client can have multiple registered URIs, this logic needs to iterate through them.
	// For now, assuming a single registered URI or the primary one.
	if strings.TrimSpace(client.RedirectURI) == "" {
		// Client has no registered redirect URI, which is an invalid configuration for the Authorization Code flow.
		log.Warn("authorize: client has no registered redirect_uri", "client_id", req.ClientID)
		return nil, ErrInvalidClient // OAuth2 spec: `invalid_client` or `invalid_request`
	}
	if !strings.EqualFold(req.RedirectURI, client.RedirectURI) {
		log.Warn("authorize: redirect_uri mismatch",
			"requested_uri", req.RedirectURI,
			"registered_uri", client.RedirectURI,
			"client_id", req.ClientID)
		return nil, ErrInvalidRedirectURI
	}

	// Validate PKCE requirements.
	challenge, method, err := validatePKCE(req.CodeChallenge, req.CodeChallengeMethod, client)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	var (
		user            domain.User
		role            domain.Role
		effectiveScopes []string
		sessionID       string
	)

	// Handle MFA completion first (highest priority if token present).
	if strings.TrimSpace(req.MFAToken) != "" {
		return s.handleMFACompletion(ctx, now, client, challenge, method, req)
	}

	// Existing authenticated session.
	if req.Session != nil {
		if strings.TrimSpace(req.Session.UserID) == "" {
			return nil, ErrInvalidGrant
		}

		user, err = s.Store.Users().GetUserByID(ctx, req.Session.UserID)
		if err != nil {
			return nil, err
		}

		role, err = s.Store.Roles().GetRoleByID(ctx, user.RoleID)
		if err != nil {
			return nil, err
		}

		requested := coalesceScopes(req.Scope, req.Session.Scopes)
		if len(requested) == 0 {
			requested = client.Scopes
		}

		effectiveScopes = intersectThreeWay(requested, client.Scopes, role.Scopes)
		if len(req.Session.Scopes) > 0 {
			effectiveScopes = intersectScopes(effectiveScopes, req.Session.Scopes)
		}
		if len(effectiveScopes) == 0 {
			return nil, ErrInvalidScope
		}

		sessionID = req.Session.SessionID
		if sessionID == "" {
			sessionID = idx.New().String()
		}

		sessionAMR := dedupe(req.Session.AMR)
		if len(sessionAMR) == 0 {
			sessionAMR = []string{jwtx.AMRPassword}
		}

		// The req.RedirectURI passed here has been validated against the client's registered URI.
		return s.issueAuthorizationCode(ctx, now, user.ID, client.ID, req.RedirectURI, req.State, challenge, method, effectiveScopes, sessionID, sessionAMR, nil)
	}

	// Interactive username/password authentication.
	username := strings.TrimSpace(req.Username)
	if username == "" || req.Password == "" {
		return nil, ErrLoginRequired
	}

	user, err = s.Store.Users().GetUserByUsername(ctx, username)
	if err != nil {
		log.Warn("authorize: user lookup failed", "error", err)
		if errors.Is(err, store.ErrNotFound) {
			return nil, ErrInvalidCredentials
		}
		return nil, err
	}

	if cryptox.VerifyPassword(req.Password, user.PasswordHash) != nil {
		return nil, ErrInvalidCredentials
	}

	role, err = s.Store.Roles().GetRoleByID(ctx, user.RoleID)
	if err != nil {
		return nil, err
	}

	requested := req.Scope
	if len(requested) == 0 {
		requested = client.Scopes
	}
	effectiveScopes = intersectThreeWay(requested, client.Scopes, role.Scopes)
	if len(effectiveScopes) == 0 {
		return nil, ErrInvalidScope
	}

	sessionID = idx.New().String()
	baseAMR := []string{jwtx.AMRPassword}

	if user.MFAEnabled != nil {
		mfaToken := idx.New().String()
		session := domain.MFASession{
			ID:          mfaToken,
			UserID:      user.ID,
			ClientID:    client.ID,
			Scopes:      effectiveScopes,
			AMR:         baseAMR,
			SessionID:   sessionID,
			RedirectURI: req.RedirectURI, // Store the validated redirect_uri in the MFA session
			CreatedAt:   now.Format(time.RFC3339),
			ExpiresAt:   now.Add(5 * time.Minute).Format(time.RFC3339),
		}

		if err := s.Store.MFASessions().CreateMFASession(ctx, session); err != nil {
			return nil, err
		}

		// Return MFA challenge using the same pattern as TokenService.ExchangePassword
		return nil, &MFARequiredError{
			MFAToken: mfaToken,
			Methods:  mfaMethods,
		}
	}

	// The req.RedirectURI passed here has been validated against the client's registered URI.
	return s.issueAuthorizationCode(ctx, now, user.ID, client.ID, req.RedirectURI, req.State, challenge, method, effectiveScopes, sessionID, baseAMR, nil)
}

func (s *AuthorizeService) handleMFACompletion(
	ctx context.Context,
	now time.Time,
	client domain.Client,
	challenge, method string,
	req AuthorizeRequest,
) (*AuthorizeCodeResponse, error) {
	log := slogx.FromContext(ctx)

	if strings.TrimSpace(req.MFAMethod) == "" || strings.TrimSpace(req.MFACode) == "" {
		return nil, ErrInvalidRequest
	}

	session, err := s.Store.MFASessions().GetMFASession(ctx, req.MFAToken)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, ErrInvalidGrant
		}
		return nil, err
	}

	// Check if max attempts exceeded
	if session.Attempts >= MaxMFAAttempts {
		// Delete the session to prevent further attempts
		_ = s.Store.MFASessions().DeleteMFASession(ctx, req.MFAToken)
		log.Warn("MFA session exceeded max attempts", "mfa_token", req.MFAToken, "attempts", session.Attempts)
		return nil, ErrTooManyAttempts
	}

	if session.ClientID != client.ID {
		return nil, ErrInvalidRequest
	}

	// CRITICAL: Ensure the redirect_uri used for MFA completion matches the one from the initial request
	// stored in the MFA session, and also matches the client's registered URI.
	if strings.TrimSpace(session.RedirectURI) == "" {
		log.Warn("MFA completion: MFA session missing redirect_uri", "mfa_token", req.MFAToken)
		return nil, ErrInvalidGrant // Corrupted MFA session
	}
	if !strings.EqualFold(req.RedirectURI, session.RedirectURI) {
		log.Warn("MFA completion: redirect_uri mismatch between initial and completion request",
			"requested_uri", req.RedirectURI,
			"session_uri", session.RedirectURI,
			"mfa_token", req.MFAToken)
		return nil, ErrInvalidRequest // OAuth2 spec suggests invalid_request for this.
	}
	// Also re-validate against the client's registered URI, though this should ideally be consistent with session.RedirectURI.
	if !strings.EqualFold(req.RedirectURI, client.RedirectURI) { // `client` is passed into this function
		log.Warn("MFA completion: redirect_uri mismatch against client's registered URI",
			"requested_uri", req.RedirectURI,
			"registered_uri", client.RedirectURI,
			"client_id", client.ID)
		return nil, ErrInvalidRedirectURI
	}

	user, err := s.Store.Users().GetUserByID(ctx, session.UserID)
	if err != nil {
		return nil, err
	}

	role, err := s.Store.Roles().GetRoleByID(ctx, user.RoleID)
	if err != nil {
		return nil, err
	}

	effectiveScopes := intersectThreeWay(session.Scopes, client.Scopes, role.Scopes)
	if len(effectiveScopes) == 0 {
		return nil, ErrInvalidScope
	}

	normalizedMethod := strings.ToLower(req.MFAMethod)
	if normalizedMethod != "totp" && normalizedMethod != "backup_codes" {
		return nil, ErrInvalidRequest
	}

	mfaSessionID := session.ID

	sessionID := session.SessionID
	if sessionID == "" {
		sessionID = idx.New().String()
	}

	baseAMR := dedupe(session.AMR)
	if len(baseAMR) == 0 {
		baseAMR = []string{jwtx.AMRPassword}
	}

	var (
		code          string
		record        domain.AuthorizationCode
		validationErr error
	)

	switch normalizedMethod {
	case "totp":
		if user.MFASecret == nil || *user.MFASecret == "" {
			validationErr = errInvalidMFACode
		} else if !totp.Validate(req.MFACode, *user.MFASecret) {
			validationErr = errInvalidMFACode
		} else {
			amr := dedupe(append(baseAMR, jwtx.AMRMFA))
			// Use the validated redirect URI stored in the MFA session.
			code, record, err = s.prepareAuthorizationCode(now, user.ID, client.ID, session.RedirectURI, challenge, method, effectiveScopes, sessionID, amr, &mfaSessionID)
			if err != nil {
				return nil, err
			}

			err = s.Store.WithTx(ctx, func(tx store.Tx) error {
				if err := tx.AuthorizationCodes().CreateAuthorizationCode(ctx, record); err != nil {
					return err
				}
				return tx.MFASessions().DeleteMFASession(ctx, session.ID)
			})
		}

	case "backup_codes":
		hashed := cryptox.FingerprintToken(req.MFACode)
		valid, err := s.Store.BackupCodes().VerifyBackupCode(ctx, user.ID, hashed)
		if err != nil {
			return nil, err
		}

		if !valid {
			validationErr = errInvalidMFACode
		} else {
			amr := dedupe(append(baseAMR, jwtx.AMRMFA))
			// Use the validated redirect URI stored in the MFA session.
			code, record, err = s.prepareAuthorizationCode(now, user.ID, client.ID, session.RedirectURI, challenge, method, effectiveScopes, sessionID, amr, &mfaSessionID)
			if err != nil {
				return nil, err
			}

			err = s.Store.WithTx(ctx, func(tx store.Tx) error {
				if err := tx.BackupCodes().DeleteBackupCode(ctx, user.ID, hashed); err != nil {
					return err
				}
				if err := tx.AuthorizationCodes().CreateAuthorizationCode(ctx, record); err != nil {
					return err
				}
				return tx.MFASessions().DeleteMFASession(ctx, session.ID)
			})
		}
	}

	// If validation failed, increment attempts and return error
	if validationErr != nil {
		updatedSession, err := s.Store.MFASessions().IncrementMFASessionAttempts(ctx, req.MFAToken)
		if err != nil {
			log.Error("MFA session increment attempts failed", "error", err, "mfa_token", req.MFAToken)
			return nil, err // Failed to increment attempts
		}
		if updatedSession.Attempts >= MaxMFAAttempts {
			// Session should already be deleted by the check at the start of handleMFACompletion,
			// but if not, an explicit delete here can be a fallback.
			// _ = s.Store.MFASessions().DeleteMFASession(ctx, session.ID) // Optional: ensure deletion
			return nil, ErrTooManyAttempts
		}
		return nil, validationErr // Return the specific MFA validation error
	}

	// If a transaction error occurred (e.g., database error during creation/deletion)
	if err != nil {
		return nil, err
	}

	// MFA successful, return the authorization code
	return &AuthorizeCodeResponse{
		Code:        code,
		RedirectURI: session.RedirectURI, // Return the validated URI from the session
		State:       req.State,
	}, nil
}

// issueAuthorizationCode generates and persists a new authorization code.
func (s *AuthorizeService) issueAuthorizationCode(
	ctx context.Context,
	now time.Time,
	userID, clientID, redirectURI, state, challenge, method string,
	scopes []string,
	sessionID string,
	amr []string,
	mfaSessionID *string,
) (*AuthorizeCodeResponse, error) {
	code, record, err := s.prepareAuthorizationCode(now, userID, clientID, redirectURI, challenge, method, scopes, sessionID, amr, mfaSessionID)
	if err != nil {
		return nil, err
	}

	if err := s.Store.AuthorizationCodes().CreateAuthorizationCode(ctx, record); err != nil {
		return nil, err
	}

	return &AuthorizeCodeResponse{
		Code:        code,
		RedirectURI: redirectURI,
		State:       state,
	}, nil
}

// prepareAuthorizationCode generates a new authorization code and the corresponding domain.AuthorizationCode record.
func (s *AuthorizeService) prepareAuthorizationCode(
	now time.Time,
	userID, clientID, redirectURI, challenge, method string,
	scopes []string,
	sessionID string,
	amr []string,
	mfaSessionID *string,
) (string, domain.AuthorizationCode, error) {
	code := idx.New().String()
	record := domain.AuthorizationCode{
		Code:                code,
		UserID:              userID,
		ClientID:            clientID,
		RedirectURI:         redirectURI, // Store the validated redirect URI with the code
		Scope:               scopes,
		State:               "",          // State is not stored with the code, but used for the final redirect
		CodeChallenge:       challenge,
		CodeChallengeMethod: method,
		SessionID:           sessionID,
		AMR:                 amr,
		MFASessionID:        mfaSessionID,
		CreatedAt:           now.Format(time.RFC3339),
		ExpiresAt:           now.Add(s.CodeTTL).Format(time.RFC3339),
	}
	return code, record, nil
}

// coalesceScopes returns the non-empty list of scopes, preferring primary over fallback.
func coalesceScopes(primary, fallback []string) []string {
	if len(primary) > 0 {
		return primary
	}
	return fallback
}

// intersectScopes returns the intersection of two string slices.
func intersectScopes(s1, s2 []string) []string {
	m := make(map[string]bool)
	for _, item := range s1 {
		m[item] = true
	}

	var intersection []string
	for _, item := range s2 {
		if m[item] {
			intersection = append(intersection, item)
		}
	}
	return intersection
}

// intersectThreeWay returns the intersection of three string slices.
func intersectThreeWay(s1, s2, s3 []string) []string {
	// First intersect s1 and s2
	m1 := make(map[string]bool)
	for _, item := range s1 {
		m1[item] = true
	}

	var tempIntersection []string
	for _, item := range s2 {
		if m1[item] {
			tempIntersection = append(tempIntersection, item)
		}
	}

	// Then intersect the result with s3
	m2 := make(map[string]bool)
	for _, item := range tempIntersection {
		m2[item] = true
	}

	var finalIntersection []string
	for _, item := range s3 {
		if m2[item] {
			finalIntersection = append(finalIntersection, item)
		}
	}
	return finalIntersection
}

// dedupe removes duplicate strings from a slice.
func dedupe(slice []string) []string {
	seen := make(map[string]struct{})
	var result []string
	for _, item := range slice {
		if _, ok := seen[item]; !ok {
			seen[item] = struct{}{}
			result = append(result, item)
		}
	}
	return result
}

// validatePKCE checks the code_challenge and code_challenge_method.
// It returns the normalized challenge and method, or an error.
// Assumption: domain.Client has an IsPublic() bool method.
func validatePKCE(codeChallenge, codeChallengeMethod string, client domain.Client) (string, string, error) {
	if client.IsPublic() { // Assuming IsPublic() method exists on domain.Client
		if strings.TrimSpace(codeChallenge) == "" {
			return "", "", ErrInvalidRequest // PKCE required for public clients
		}
	}

	method := strings.TrimSpace(strings.ToLower(codeChallengeMethod))
	challenge := strings.TrimSpace(codeChallenge)

	if challenge != "" {
		// If a challenge is provided, method must be 'S256' or 'plain'.
		// If method is empty, default to S256 (recommended by RFC 7636).
		if method == "" || strings.EqualFold(method, "s256") {
			method = "S256"
		} else if strings.EqualFold(method, "plain") {
			// "plain" method is allowed but discouraged.
			method = "plain"
		} else {
			return "", "", ErrInvalidRequest // Unsupported code_challenge_method
		}
	} else {
		// No challenge provided. This is only allowed for confidential clients.
		// Method should also be empty if no challenge.
		if method != "" {
			return "", "", ErrInvalidRequest // Method provided without challenge
		}
	}

	return challenge, method, nil
}