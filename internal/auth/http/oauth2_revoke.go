package http

import (
	"net/http"
	"strings"

	"github.com/aussiebroadwan/bartab/internal/auth/service"
	"github.com/aussiebroadwan/bartab/pkg/authsdk"
	"github.com/aussiebroadwan/bartab/pkg/httpx"
	"github.com/aussiebroadwan/bartab/pkg/slogx"
)

// RevokeHandler serves POST /v1/oauth2/revoke following the RFC 7009 spec. It
// will currently revoke refresh tokens only. Access tokens expire naturally.
// All tokens even if invalid/unknown return 200 OK to prevent token scanning
// attacks.
type RevokeHandler struct {
	TokenService *service.TokenService
}

// ServeHTTP godoc
//
//	@Summary		OAuth2 Token Revocation Endpoint
//	@Description	Revokes a previously issued token (RFC 7009)
//	@Description	Currently supports revoking refresh tokens only. Access tokens expire naturally.
//	@Description	The endpoint is idempotent and returns 200 OK even for invalid/unknown tokens to prevent token scanning attacks.
//	@Tags			OAuth2
//	@Accept			application/x-www-form-urlencoded
//	@Produce		json
//	@Param			token			formData	string	true	"The token to revoke"
//	@Param			token_type_hint	formData	string	false	"Hint about token type"	Enums(access_token, refresh_token)
//	@Success		200				"Token revoked successfully (or was already invalid)"
//	@Failure		400				{object}	map[string]string	"error, error_description"
//	@Failure		405				{object}	map[string]string	"error, error_description"
//	@Header			200				{string}	Cache-Control		"no-store"
//	@Header			200				{string}	Pragma				"no-cache"
//	@Router			/v1/oauth2/revoke [post].
func (h *RevokeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := slogx.FromContext(ctx)

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

	token := r.Form.Get("token")
	tokenTypeHint := r.Form.Get("token_type_hint")

	if token == "" {
		authsdk.ErrInvalidRequest.WriteError(w)
		return
	}

	// 3. Revoke the token. We currently only support refresh tokens at the moment.
	if tokenTypeHint == "" || tokenTypeHint == "refresh_token" {
		if err := h.TokenService.RevokeRefreshToken(ctx, token); err != nil {
			// Per RFC 7009, the server responds 200 OK even if the token is invalid/unknown.
			log.Warn("revoke refresh failed", "err", err)
		}
	}

	// 4. Return 200 OK with empty body per spec
	httpx.NoCache(w)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("{}"))
}
