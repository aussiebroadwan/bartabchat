package authsdk

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// MintInvite creates a new invite token.
// Requires: admin:write scope
// Automatically refreshes the access token if expired.
func (s *Session) MintInvite(ctx context.Context, req InviteRequest) (*InviteResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	headers := map[string]string{
		"Content-Type": "application/json",
	}

	resp, err := s.doAuthRequest(
		ctx,
		http.MethodPost,
		"/v1/invites/mint",
		bytes.NewReader(body),
		headers,
		"admin:write",
	)
	if err != nil {
		return nil, err
	}

	var inviteResp InviteResponse
	if err := decodeJSON(resp, &inviteResp, http.StatusOK); err != nil {
		return nil, err
	}

	return &inviteResp, nil
}
