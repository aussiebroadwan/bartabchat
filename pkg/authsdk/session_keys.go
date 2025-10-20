package authsdk

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// RotateKey rotates the JWT signing keys by generating a new key.
// Requires: admin:write scope
// Automatically refreshes the access token if expired.
func (s *Session) RotateKey(ctx context.Context, req RotateKeyRequest) (*RotateKeyResponse, error) {
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
		"/v1/keys/rotate",
		bytes.NewReader(body),
		headers,
		"admin:write",
	)
	if err != nil {
		return nil, err
	}

	var rotateResp RotateKeyResponse
	if err := decodeJSON(resp, &rotateResp, http.StatusOK); err != nil {
		return nil, err
	}

	return &rotateResp, nil
}

// ListKeys returns all signing keys with their status.
// Requires: admin:read scope
// Automatically refreshes the access token if expired.
func (s *Session) ListKeys(ctx context.Context) ([]SigningKeyInfo, error) {
	resp, err := s.doAuthRequest(ctx, http.MethodGet, "/v1/keys", nil, nil, "admin:read")
	if err != nil {
		return nil, err
	}

	var keys []SigningKeyInfo
	if err := decodeJSON(resp, &keys, http.StatusOK); err != nil {
		return nil, err
	}

	return keys, nil
}

// RetireKey retires a specific signing key by its key ID (kid).
// Requires: admin:write scope
// Automatically refreshes the access token if expired.
func (s *Session) RetireKey(ctx context.Context, kid string) error {
	path := fmt.Sprintf("/v1/keys/%s/retire", kid)

	resp, err := s.doAuthRequest(
		ctx,
		http.MethodPost,
		path,
		nil,
		nil,
		"admin:write",
	)
	if err != nil {
		return err
	}

	return checkStatusNoContent(resp)
}
