package http

import (
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/aussiebroadwan/bartab/internal/auth/service"
	"github.com/aussiebroadwan/bartab/pkg/authsdk"
	"github.com/aussiebroadwan/bartab/pkg/httpx"
	"github.com/aussiebroadwan/bartab/pkg/slogx"
)

// TokenHandler serves POST /v1/oauth2/token
// Accepts application/x-www-form-urlencoded per the RFC 6749 framework.
type TokenHandler struct {
	TokenService *service.TokenService
}

// ServeHTTP godoc
//
//	@Summary		OAuth2 Token Endpoint
//	@Description	Issues access and refresh tokens using OAuth2 grant types (authorization_code, refresh_token, client_credentials, mfa_otp).
//	@Tags			OAuth2
//	@Accept			application/x-www-form-urlencoded
//	@Produce		json
//	@Param			grant_type		formData	string					true	"Grant type"	Enums(authorization_code, refresh_token, client_credentials, mfa_otp)
//	@Param			code			formData	string					false	"Authorization code (required for authorization_code grant)"
//	@Param			redirect_uri	formData	string					false	"Redirect URI (required for authorization_code grant)"
//	@Param			code_verifier	formData	string					false	"PKCE code_verifier (required when PKCE was used)"
//	@Param			refresh_token	formData	string					false	"Refresh token (required for refresh_token grant)"
//	@Param			client_id		formData	string					true	"Client identifier (required for all grants)"
//	@Param			client_secret	formData	string					false	"Client secret (required for confidential clients)"
//	@Param			scope			formData	string					false	"Space-delimited list of scopes"
//	@Param			mfa_token		formData	string					false	"MFA token (required for mfa_otp grant)"
//	@Param			method			formData	string					false	"MFA method (required for mfa_otp grant) - totp or backup_codes"
//	@Param			otp_code		formData	string					false	"OTP code (required for mfa_otp grant)"
//	@Success		200				{object}	authsdk.TokenResponse	"access_token, refresh_token, token_type, expires_in, scope"
//	@Failure		400				{object}	authsdk.ErrorResponse	"error, error_description"
//	@Failure		401				{object}	authsdk.ErrorResponse	"error, error_description"
//	@Failure		405				{object}	authsdk.ErrorResponse	"error, error_description"
//	@Failure		500				{object}	authsdk.ErrorResponse	"error, error_description"
//	@Header			200				{string}	Cache-Control			"no-store"
//	@Header			200				{string}	Pragma					"no-cache"
//	@Router			/v1/oauth2/token [post].
func (h *TokenHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// 1. Ensure the right content-type
	if ct := r.Header.Get("Content-Type"); ct != "" &&
		!strings.HasPrefix(ct, "application/x-www-form-urlencoded") {
		authsdk.ErrInvalidContentType.WriteError(w)
		return
	}

	// 2. Parse the form body
	if err := r.ParseForm(); err != nil {
		authsdk.ErrInvalidFormBody.WriteError(w)
		return
	}

	// 3. Handle the grant type
	grantType := r.Form.Get("grant_type")
	switch grantType {
	case "authorization_code":
		h.handleAuthorizationCodeGrant(w, r, r.Form)
	case "refresh_token":
		h.handleRefreshGrant(w, r, r.Form)
	case "mfa_otp":
		h.handleMFAOTPGrant(w, r, r.Form)
	case "client_credentials":
		h.handleClientCredentialsGrant(w, r, r.Form)
	default:
		authsdk.ErrUnsupportedGrantType.WriteError(w)
	}
}

func (h *TokenHandler) handleAuthorizationCodeGrant(
	w http.ResponseWriter,
	r *http.Request,
	form url.Values,
) {
	ctx := r.Context()
	log := slogx.FromContext(ctx)

	code := strings.TrimSpace(form.Get("code"))
	redirectURI := strings.TrimSpace(form.Get("redirect_uri"))
	clientID := strings.TrimSpace(form.Get("client_id"))
	codeVerifier := strings.TrimSpace(form.Get("code_verifier"))
	clientSecret := form.Get("client_secret")

	if code == "" || redirectURI == "" || clientID == "" {
		authsdk.ErrInvalidRequest.WriteError(w)
		return
	}

	pair, err := h.TokenService.ExchangeAuthorizationCode(ctx, clientID, clientSecret, code, redirectURI, codeVerifier)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrInvalidClient):
			authsdk.ErrInvalidClient.WriteError(w)
		case errors.Is(err, service.ErrInvalidGrant):
			authsdk.ErrInvalidGrant.WriteError(w)
		case errors.Is(err, service.ErrInvalidScope):
			authsdk.ErrInvalidScope.WriteError(w)
		default:
			log.Error("authorization_code grant failed", "err", err)
			authsdk.ErrServerError.WriteError(w)
		}
		return
	}

	response := authsdk.TokenResponse{
		AccessToken:  pair.AccessToken,
		RefreshToken: pair.RefreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int(pair.ExpiresIn.Seconds()),
		Scope:        strings.TrimSpace(pair.Scope),
	}

	httpx.NoCache(w)
	httpx.WriteJSON(w, http.StatusOK, response)
}

func (h *TokenHandler) handleRefreshGrant(w http.ResponseWriter, r *http.Request, form url.Values) {
	ctx := r.Context()
	log := slogx.FromContext(ctx)

	refresh := form.Get("refresh_token")
	clientID := strings.TrimSpace(form.Get("client_id"))
	scopeStr := strings.TrimSpace(form.Get("scope"))
	requested := httpx.ParseSpaceDelimitedFields(scopeStr)

	if refresh == "" || clientID == "" {
		authsdk.ErrInvalidRequest.WriteError(w)
		return
	}

	pair, err := h.TokenService.ExchangeRefreshToken(ctx, clientID, refresh, requested)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrInvalidRefresh):
			authsdk.ErrInvalidGrant.WriteError(w)
		case errors.Is(err, service.ErrInvalidClient):
			authsdk.ErrInvalidClient.WriteError(w)
		case errors.Is(err, service.ErrInvalidScope):
			authsdk.ErrInvalidScope.WriteError(w)
		default:
			log.Error("refresh grant failed", "err", err)
			authsdk.ErrServerError.WriteError(w)
		}
		return
	}

	response := authsdk.TokenResponse{
		AccessToken:  pair.AccessToken,
		RefreshToken: pair.RefreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int(pair.ExpiresIn.Seconds()),
		Scope:        strings.TrimSpace(pair.Scope),
	}

	httpx.NoCache(w)
	httpx.WriteJSON(w, http.StatusOK, response)
}

func (h *TokenHandler) handleMFAOTPGrant(w http.ResponseWriter, r *http.Request, form url.Values) {
	ctx := r.Context()
	log := slogx.FromContext(ctx)

	mfaToken := strings.TrimSpace(form.Get("mfa_token"))
	method := strings.TrimSpace(form.Get("method"))
	otpCode := strings.TrimSpace(form.Get("otp_code"))

	if mfaToken == "" || method == "" || otpCode == "" {
		authsdk.ErrInvalidRequest.WriteError(w)
		return
	}

	pair, err := h.TokenService.ExchangeMFAOTP(ctx, mfaToken, method, otpCode)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrTooManyAttempts):
			log.Warn("MFA OTP grant failed: too many attempts", "mfa_token", mfaToken)
			authsdk.NewOAuth2Error(
				http.StatusUnauthorized,
				"invalid_grant",
				"Too many failed attempts. MFA session has been invalidated.",
			).WriteError(w)
		case errors.Is(err, service.ErrInvalidGrant):
			log.Warn("MFA OTP grant failed: invalid grant", "err", err)
			authsdk.ErrInvalidGrant.WriteError(w)
		default:
			log.Error("MFA OTP grant failed", "err", err)
			authsdk.ErrServerError.WriteError(w)
		}
		return
	}

	response := authsdk.TokenResponse{
		AccessToken:  pair.AccessToken,
		RefreshToken: pair.RefreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int(pair.ExpiresIn.Seconds()),
		Scope:        strings.TrimSpace(pair.Scope),
	}

	httpx.NoCache(w)
	httpx.WriteJSON(w, http.StatusOK, response)
}

func (h *TokenHandler) handleClientCredentialsGrant(
	w http.ResponseWriter,
	r *http.Request,
	form url.Values,
) {
	ctx := r.Context()
	log := slogx.FromContext(ctx)

	clientID := strings.TrimSpace(form.Get("client_id"))
	clientSecret := form.Get("client_secret")
	scopeStr := strings.TrimSpace(form.Get("scope"))
	requested := httpx.ParseSpaceDelimitedFields(scopeStr)

	// Both client_id and client_secret are required for client_credentials grant
	if clientID == "" || clientSecret == "" {
		authsdk.ErrInvalidRequest.WriteError(w)
		return
	}

	pair, err := h.TokenService.ExchangeClientCredentials(ctx, clientID, clientSecret, requested)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrInvalidClient):
			authsdk.ErrInvalidClient.WriteError(w)
		case errors.Is(err, service.ErrInvalidScope):
			authsdk.ErrInvalidScope.WriteError(w)
		default:
			log.Error("client_credentials grant failed", "err", err)
			authsdk.ErrServerError.WriteError(w)
		}
		return
	}

	// Build response
	// NOTE: omit refresh_token if empty (as per OAuth2 spec)
	response := authsdk.TokenResponse{
		AccessToken: pair.AccessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int(pair.ExpiresIn.Seconds()),
		Scope:       strings.TrimSpace(pair.Scope),
	}

	httpx.NoCache(w)
	httpx.WriteJSON(w, http.StatusOK, response)
}
