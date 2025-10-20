package http

import (
	"net/http"
	"strings"

	"github.com/aussiebroadwan/bartab/pkg/authsdk"
	"github.com/aussiebroadwan/bartab/pkg/httpx"
	"github.com/aussiebroadwan/bartab/pkg/jwtx"
	"github.com/aussiebroadwan/bartab/pkg/slogx"
)

// IntrospectionResponse represents the RFC7662 introspection response.
// When a token is inactive, only the "active" field should be returned.
type IntrospectionResponse struct {
	Active bool `json:"active"`

	// Optional fields (only present when active=true)
	Scope         string   `json:"scope,omitempty"`
	ClientID      string   `json:"client_id,omitempty"`
	Username      string   `json:"username,omitempty"`
	TokenType     string   `json:"token_type,omitempty"`
	Exp           int64    `json:"exp,omitempty"`
	Iat           int64    `json:"iat,omitempty"`
	Nbf           int64    `json:"nbf,omitempty"`
	Sub           string   `json:"sub,omitempty"`
	Aud           []string `json:"aud,omitempty"`
	Iss           string   `json:"iss,omitempty"`
	Jti           string   `json:"jti,omitempty"`
	SessionID     string   `json:"sid,omitempty"`
	AMR           []string `json:"amr,omitempty"`
	PreferredName string   `json:"preferred_name,omitempty"`
}

// IntrospectHandler serves POST /v1/oauth2/introspect following RFC7662.
// It verifies the provided token and returns metadata about it.
type IntrospectHandler struct {
	Verifier jwtx.Verifier
}

// ServeHTTP godoc
//
//	@Summary		OAuth2 Token Introspection Endpoint
//	@Description	Introspects a token and returns metadata about it (RFC 7662)
//	@Tags			OAuth2
//	@Accept			application/x-www-form-urlencoded
//	@Produce		json
//	@Security		BearerAuth
//	@Param			token			formData	string					true	"The token to introspect"
//	@Param			token_type_hint	formData	string					false	"Hint about token type (currently only 'access_token' is supported)"	Enums(access_token)
//	@Success		200				{object}	IntrospectionResponse	"Token introspection result"
//	@Failure		400				{object}	map[string]string		"error, error_description"
//	@Failure		401				{object}	map[string]string		"error, error_description"
//	@Header			200				{string}	Cache-Control			"no-store"
//	@Header			200				{string}	Pragma					"no-cache"
//	@Router			/v1/oauth2/introspect [post].
func (h *IntrospectHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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

	// 3. We only support introspecting access tokens (JWTs)
	// If hint is provided and it's not access_token, return inactive
	if tokenTypeHint != "" && tokenTypeHint != "access_token" {
		// Per RFC7662, return active=false without revealing why
		writeInactiveResponse(w)
		return
	}

	// 4. Verify the token using our JWT verifier
	claims, err := h.Verifier.Verify(token)
	if err != nil {
		log.Debug("token verification failed during introspection", "error", err)

		// Per RFC7662, return active=false without revealing why
		writeInactiveResponse(w)
		return
	}

	// 5. Check if token is expired or not yet valid
	if err := claims.ValidateExpiry(); err != nil {
		log.Debug("token failed expiry check during introspection", "error", err)

		// Per RFC7662, return active=false without revealing why
		writeInactiveResponse(w)
		return
	}

	// 6. Build the introspection response
	response := IntrospectionResponse{
		Active:        true,
		Scope:         strings.Join(claims.Scopes, " "),
		TokenType:     "Bearer",
		Sub:           claims.Subject,
		Username:      claims.Username,
		Iss:           claims.Issuer,
		SessionID:     claims.SID,
		AMR:           claims.AMR,
		PreferredName: claims.PreferredName,
		Jti:           claims.ID,
	}

	// Extract audience (client_id is first audience value)
	if len(claims.Audience) > 0 {
		response.ClientID = claims.Audience[0]
		response.Aud = claims.Audience
	}

	// Extract timestamps
	if claims.ExpiresAt != nil {
		response.Exp = claims.ExpiresAt.Unix()
	}
	if claims.IssuedAt != nil {
		response.Iat = claims.IssuedAt.Unix()
	}
	if claims.NotBefore != nil {
		response.Nbf = claims.NotBefore.Unix()
	}

	// 7. Return the response with no-cache headers
	httpx.NoCache(w)
	httpx.WriteJSON(w, http.StatusOK, response)
}

// writeInactiveResponse returns the minimal RFC7662 response for inactive tokens.
func writeInactiveResponse(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusOK)

	// Per RFC7662: "If the token is not active, does not exist on this server,
	// or the protected resource is not allowed to introspect this particular token,
	// then the authorization server MUST return an introspection response with
	// the 'active' field set to 'false'"
	_, _ = w.Write([]byte(`{"active":false}`))
}
