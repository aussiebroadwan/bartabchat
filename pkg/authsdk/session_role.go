package authsdk

import (
	"context"
	"net/http"
)

// ListRoles retrieves all available roles.
// Requires: admin:read scope
// Automatically refreshes the access token if expired.
func (s *Session) ListRoles(ctx context.Context) (*ListRolesResponse, error) {
	resp, err := s.doAuthRequest(ctx, http.MethodGet, "/v1/roles", nil, nil, "admin:read")
	if err != nil {
		return nil, err
	}

	var rolesResp ListRolesResponse
	if err := decodeJSON(resp, &rolesResp, http.StatusOK); err != nil {
		return nil, err
	}

	return &rolesResp, nil
}
