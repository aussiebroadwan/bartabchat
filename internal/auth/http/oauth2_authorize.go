package http

import (
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/aussiebroadwan/bartab/internal/auth/service"
	"github.com/aussiebroadwan/bartab/pkg/authsdk"
	"github.com/aussiebroadwan/bartab/pkg/httpx"
	"github.com/aussiebroadwan/bartab/pkg/jwtx"
	"github.com/aussiebroadwan/bartab/pkg/slogx"
)

const (
	sessionCookieName = "bartab_session"
)

// AuthorizeHandler processes OAuth2 authorization requests (authorization code flow).
type AuthorizeHandler struct {
	AuthorizeService *service.AuthorizeService
	Verifier         jwtx.Verifier
	Logger           *slog.Logger
}

// HandleGet processes GET requests to the authorization endpoint.
// This is used when the user's browser is redirected to begin the authorization flow.
//
//	@Summary		OAuth2 authorization endpoint (GET)
//	@Description	Initiates the OAuth2 authorization code flow via GET request. Used for browser redirects.
//	@Description	If a valid session exists (cookie or Bearer token), issues authorization code immediately.
//	@Description	Otherwise, returns 401 with login_required error.
//	@Description
//	@Description	**PKCE Support:**
//	@Description	- Public clients MUST include code_challenge (defaults to S256 if method omitted)
//	@Description	- Confidential clients MAY include code_challenge for additional security
//	@Description
//	@Description	**Response:**
//	@Description	- Success: 302 redirect to redirect_uri with code and state parameters
//	@Description	- No session: 401 JSON with login_required error
//	@Description	- Error: JSON error response
//	@Tags			OAuth2
//	@Produce		json
//	@Param			response_type			query		string					true	"Must be 'code'"	default(code)
//	@Param			client_id				query		string					true	"OAuth2 client identifier"
//	@Param			redirect_uri			query		string					true	"Callback URI (must match registered redirect URI)"
//	@Param			scope					query		string					false	"Space-delimited list of scopes"	example("profile:read admin:write")
//	@Param			state					query		string					false	"Opaque value for CSRF protection (recommended)"
//	@Param			code_challenge			query		string					false	"PKCE code challenge (required for public clients)"	example("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
//	@Param			code_challenge_method	query		string					false	"PKCE method (S256 or plain, defaults to S256)"		default(S256)	Enums(S256, plain)
//	@Success		302						{string}	string					"Redirect to redirect_uri with code and state"
//	@Failure		400						{object}	map[string]interface{}	"Invalid request"	example({"error":"invalid_request","error_description":"missing required parameter"})
//	@Failure		401						{object}	map[string]interface{}	"Unauthorized"		example({"error":"login_required","error_description":"user authentication required"})
//	@Router			/v1/oauth2/authorize [get]
func (h *AuthorizeHandler) HandleGet(w http.ResponseWriter, r *http.Request) {
	if h.AuthorizeService == nil {
		authsdk.ErrServerError.WriteError(w)
		return
	}

	query := r.URL.Query()
	authReq := h.buildAuthorizeRequest(nil, query)
	if session := h.resolveSession(r); session != nil {
		authReq.Session = session
		h.processAuthorize(w, r, authReq)
		return
	}

	payload := map[string]any{
		"error":             "login_required",
		"error_description": "user authentication required",
		"response_type":     authReq.ResponseType,
		"client_id":         authReq.ClientID,
		"redirect_uri":      authReq.RedirectURI, // Note: This redirect_uri has not been validated at this point
	}
	if len(authReq.Scope) > 0 {
		payload["scope"] = strings.Join(authReq.Scope, " ")
	}
	if authReq.State != "" {
		payload["state"] = authReq.State
	}
	httpx.WriteJSON(w, http.StatusUnauthorized, payload)
}

// HandlePost processes POST requests to the authorization endpoint.
// This is used for direct authentication with username/password or MFA completion.
//
//	@Summary		OAuth2 authorization endpoint (POST)
//	@Description	Initiates the OAuth2 authorization code flow via POST request with credentials.
//	@Description	Supports three authentication methods:
//	@Description	- Session-based: Include session cookie or Bearer token in Authorization header
//	@Description	- Username/Password: Submit credentials in POST body
//	@Description	- MFA Completion: Submit mfa_token with mfa_method and mfa_code
//	@Description
//	@Description	**PKCE Support:**
//	@Description	- Public clients MUST include code_challenge (defaults to S256 if method omitted)
//	@Description	- Confidential clients MAY include code_challenge for additional security
//	@Description
//	@Description	**Response:**
//	@Description	- Success: 302 redirect to redirect_uri with code and state parameters
//	@Description	- MFA Required: 409 JSON response with mfa_token and available methods
//	@Description	- Error: Either redirect with error parameters or JSON error response
//	@Tags			OAuth2
//	@Accept			x-www-form-urlencoded
//	@Produce		json
//	@Param			response_type			query		string					true	"Must be 'code'"	default(code)
//	@Param			client_id				query		string					true	"OAuth2 client identifier"
//	@Param			redirect_uri			query		string					true	"Callback URI (must match registered redirect URI)"
//	@Param			scope					query		string					false	"Space-delimited list of scopes"	example("profile:read admin:write")
//	@Param			state					query		string					false	"Opaque value for CSRF protection (recommended)"
//	@Param			code_challenge			query		string					false	"PKCE code challenge (required for public clients)"	example("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
//	@Param			code_challenge_method	query		string					false	"PKCE method (S256 or plain, defaults to S256)"		default(S256)	Enums(S256, plain)
//	@Param			username				formData	string					false	"Username for password authentication"
//	@Param			password				formData	string					false	"Password for password authentication"
//	@Param			mfa_token				formData	string					false	"MFA token from previous 409 response"
//	@Param			mfa_method				formData	string					false	"MFA method (totp or backup_codes)"	Enums(totp, backup_codes)
//	@Param			mfa_code				formData	string					false	"MFA code (6-digit TOTP or backup code)"
//	@Success		302						{string}	string					"Redirect to redirect_uri with code and state"
//	@Success		409						{object}	map[string]interface{}	"MFA required"		example({"error":"mfa_required","error_description":"multi-factor authentication is required","mfa_token":"token123","mfa_methods":["totp","backup_codes"]})
//	@Failure		400						{object}	map[string]interface{}	"Invalid request"	example({"error":"invalid_request","error_description":"missing required parameter"})
//	@Failure		401						{object}	map[string]interface{}	"Unauthorized"		example({"error":"login_required","error_description":"user authentication required"})
//	@Router			/v1/oauth2/authorize [post]
func (h *AuthorizeHandler) HandlePost(w http.ResponseWriter, r *http.Request) {
	if h.AuthorizeService == nil {
		authsdk.ErrServerError.WriteError(w)
		return
	}

	if ct := r.Header.Get("Content-Type"); ct != "" && !strings.HasPrefix(ct, "application/x-www-form-urlencoded") {
		authsdk.ErrInvalidContentType.WriteError(w)
		return
	}

	if err := r.ParseForm(); err != nil {
		authsdk.ErrInvalidFormBody.WriteError(w)
		return
	}

	authReq := h.buildAuthorizeRequest(r.Form, r.URL.Query())
	if session := h.resolveSession(r); session != nil {
		authReq.Session = session
	}
	authReq.Username = strings.TrimSpace(r.Form.Get("username"))
	authReq.Password = r.Form.Get("password")

	h.processAuthorize(w, r, authReq)
}

func (h *AuthorizeHandler) buildAuthorizeRequest(primary, secondary url.Values) service.AuthorizeRequest {
	pick := func(key string) string {
		if primary != nil {
			if v := strings.TrimSpace(primary.Get(key)); v != "" {
				return v
			}
		}
		if secondary != nil {
			return strings.TrimSpace(secondary.Get(key))
		}
		return ""
	}

	scopeStr := pick("scope")

	return service.AuthorizeRequest{
		ResponseType:        pick("response_type"),
		ClientID:            pick("client_id"),
		RedirectURI:         pick("redirect_uri"),
		Scope:               httpx.ParseSpaceDelimitedFields(scopeStr),
		State:               pick("state"),
		CodeChallenge:       pick("code_challenge"),
		CodeChallengeMethod: pick("code_challenge_method"),
		MFAToken:            pick("mfa_token"),
		MFAMethod:           pick("mfa_method"),
		MFACode:             pick("mfa_code"),
	}
}

func (h *AuthorizeHandler) processAuthorize(w http.ResponseWriter, r *http.Request, req service.AuthorizeRequest) {
	ctx := r.Context()
	logger := h.logger()

	resp, err := h.AuthorizeService.IssueAuthorizationCode(ctx, req)
	if err != nil {
		h.handleAuthorizeError(w, r, req, err, logger)
		return
	}

	// Success: build redirect URL with authorization code
	redirectURL, err := buildAuthorizeRedirect(resp.RedirectURI, resp.Code, resp.State)
	if err != nil {
		logger.Error("failed to build redirect URL", "error", err)
		authsdk.ErrServerError.WriteError(w)
		return
	}

	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func (h *AuthorizeHandler) handleAuthorizeError(w http.ResponseWriter, r *http.Request, req service.AuthorizeRequest, err error, logger *slog.Logger) {
	// Check for MFA required error (similar to TokenHandler pattern)
	var mfaErr *service.MFARequiredError
	if errors.As(err, &mfaErr) {
		// Return 409 Conflict with MFA challenge
		payload := map[string]any{
			"error":             "mfa_required",
			"error_description": "multi-factor authentication is required",
			"mfa_token":         mfaErr.MFAToken,
			"mfa_methods":       mfaErr.Methods,
		}
		httpx.WriteJSON(w, http.StatusConflict, payload)
		return
	}

	// As per OAuth2 spec (RFC 6749, Section 3.1.2.3), if the 'redirect_uri' parameter
	// is invalid or does not match a registered URI, the client MUST NOT automatically
	// redirect the user-agent to the invalid redirection URI.
	// An error message SHOULD be displayed to the user.
	if errors.Is(err, service.ErrRedirectURIMismatch) {
		oauthError := authsdk.NewOAuth2Error(
			http.StatusBadRequest,
			"invalid_request", // OAuth2 error code as per RFC 6749 Section 4.1.2.1
			"The 'redirect_uri' parameter is invalid or does not match a registered URI for the client.", // Description
		)
		oauthError.WriteError(w) // Write JSON error directly, no redirect.
		logger.Debug("authorize request failed due to redirect_uri_mismatch", slog.String("client_id", req.ClientID), slog.String("redirect_uri", req.RedirectURI))
		return
	}

	// Map service errors to HTTP responses and optionally redirect
	var (
		oauthError *authsdk.OAuth2Error
		errorCode  string
		statusCode int
	)

	switch {
	case errors.Is(err, service.ErrInvalidClient):
		oauthError = authsdk.ErrInvalidClient
		errorCode = "invalid_client"
		statusCode = http.StatusUnauthorized
	case errors.Is(err, service.ErrTooManyAttempts):
		oauthError = authsdk.NewOAuth2Error(
			http.StatusUnauthorized,
			"invalid_grant",
			"Too many failed attempts. MFA session has been invalidated.",
		)
		errorCode = "invalid_grant"
		statusCode = http.StatusUnauthorized
	case errors.Is(err, service.ErrInvalidGrant):
		oauthError = authsdk.ErrInvalidGrant
		errorCode = "invalid_grant"
		statusCode = http.StatusUnauthorized
	case errors.Is(err, service.ErrInvalidScope):
		oauthError = authsdk.ErrInvalidScope
		errorCode = "invalid_scope"
		statusCode = http.StatusBadRequest
	case errors.Is(err, service.ErrInvalidRequest):
		oauthError = authsdk.ErrInvalidRequest
		errorCode = "invalid_request"
		statusCode = http.StatusBadRequest
	case errors.Is(err, service.ErrLoginRequired):
		errorCode = "login_required"
		statusCode = http.StatusUnauthorized
	case errors.Is(err, service.ErrInvalidCredentials):
		oauthError = authsdk.ErrInvalidGrant
		errorCode = "invalid_grant"
		statusCode = http.StatusUnauthorized
	default:
		logger.Error("authorize request failed", "error", err)
		authsdk.ErrServerError.WriteError(w)
		return
	}

	// For OAuth2 spec compliance, try to redirect errors to redirect_uri if available
	// This branch is only taken if the error was NOT a redirect_uri_mismatch
	if req.RedirectURI != "" && errorCode != "" {
		redirectURL := buildErrorRedirect(req.RedirectURI, req.State, errorCode, oauthError)
		if redirectURL != "" {
			http.Redirect(w, r, redirectURL, http.StatusFound)
			return
		}
	}

	// Fallback: return JSON error response
	if oauthError != nil {
		oauthError.WriteError(w)
	} else {
		// For login_required, return a custom response
		payload := map[string]any{
			"error":             errorCode,
			"error_description": "user authentication is required",
		}
		httpx.WriteJSON(w, statusCode, payload)
	}

	logger.Debug("authorize request returned error response", "error_code", errorCode)
}

func (h *AuthorizeHandler) resolveSession(r *http.Request) *service.SessionContext {
	token := extractBearerToken(r)
	if token == "" {
		if cookie, err := r.Cookie(sessionCookieName); err == nil {
			token = cookie.Value
		}
	}

	if token == "" {
		return nil
	}

	claims, err := h.Verifier.Verify(token)
	if err != nil {
		h.logger().Debug("failed to verify session token", "error", err)
		return nil
	}

	userID, ok := claims.Subject()
	if !ok || userID == "" {
		h.logger().Warn("session token has no subject (user ID)")
		return nil
	}

	session := &service.SessionContext{
		UserID:    userID,
		UserAgent: r.UserAgent(),
		IPAddress: httpx.GetRemoteIP(r),
	}
	return session
}

func (h *AuthorizeHandler) logger() *slog.Logger {
	if h.Logger != nil {
		return h.Logger
	}
	return slogx.Discard()
}

// buildAuthorizeRedirect constructs a redirect URL for a successful authorization.
func buildAuthorizeRedirect(baseURI, code, state string) (string, error) {
	u, err := url.Parse(baseURI)
	if err != nil {
		return "", err
	}

	q := u.Query()
	q.Set("code", code)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()

	return u.String(), nil
}

// buildErrorRedirect constructs a redirect URL for an OAuth2 error.
// It returns an empty string if the baseURI is invalid.
func buildErrorRedirect(baseURI, state, errorCode string, oauthError *authsdk.OAuth2Error) string {
	u, err := url.Parse(baseURI)
	if err != nil {
		return ""
	}

	q := u.Query()
	q.Set("error", errorCode)
	if oauthError != nil && oauthError.Description != "" {
		q.Set("error_description", oauthError.Description)
	}
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()

	return u.String()
}

// extractBearerToken extracts the bearer token from the Authorization header.
func extractBearerToken(r *http.Request) string {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return ""
	}
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) == 2 && strings.ToLower(parts[0]) == "bearer" {
		return parts[1]
	}
	return ""
}