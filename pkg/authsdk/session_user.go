package authsdk

import (
	"context"
	"net/http"
	"net/url"
	"strings"
)

// User operations - standard user-facing operations

// ============================================================================
// User Information
// ============================================================================

// GetUserInfo retrieves user information for the authenticated session.
// Requires: profile:read scope
// Automatically refreshes the access token if expired.
func (s *Session) GetUserInfo(ctx context.Context) (*UserInfoResponse, error) {
	resp, err := s.doAuthRequest(ctx, http.MethodGet, "/v1/userinfo", nil, nil, "profile:read")
	if err != nil {
		return nil, err
	}

	var userInfo UserInfoResponse
	if err := decodeJSON(resp, &userInfo, http.StatusOK); err != nil {
		return nil, err
	}

	return &userInfo, nil
}

// ============================================================================
// Token Operations
// ============================================================================

// IntrospectToken introspects a token per RFC7662.
// Requires: authenticated session (no specific scope required)
// Automatically refreshes the access token if expired.
func (s *Session) IntrospectToken(ctx context.Context, tokenToIntrospect string) (*IntrospectionResponse, error) {
	data := url.Values{
		"token":           {tokenToIntrospect},
		"token_type_hint": {"access_token"},
	}

	headers := map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
	}

	resp, err := s.doAuthRequest(
		ctx,
		http.MethodPost,
		"/v1/oauth2/introspect",
		strings.NewReader(data.Encode()),
		headers,
	)
	if err != nil {
		return nil, err
	}

	var introspectResp IntrospectionResponse
	if err := decodeJSON(resp, &introspectResp, http.StatusOK); err != nil {
		return nil, err
	}

	return &introspectResp, nil
}
