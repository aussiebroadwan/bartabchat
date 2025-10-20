package authsdk

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// Admin operations - require admin:read or admin:write scopes

// ============================================================================
// Client Operations
// ============================================================================

// CreateClient creates a new OAuth2 client.
// Requires: admin:write scope
// Automatically refreshes the access token if expired.
func (s *Session) CreateClient(ctx context.Context, req CreateClientRequest) (*CreateClientResponse, error) {
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
		"/v1/clients",
		bytes.NewReader(body),
		headers,
		"admin:write",
	)
	if err != nil {
		return nil, err
	}

	var createResp CreateClientResponse
	if err := decodeJSON(resp, &createResp, http.StatusCreated); err != nil {
		return nil, err
	}

	return &createResp, nil
}

// ListClients returns all OAuth2 clients.
// Requires: admin:read scope
// Automatically refreshes the access token if expired.
func (s *Session) ListClients(ctx context.Context) (*ListClientsResponse, error) {
	resp, err := s.doAuthRequest(ctx, http.MethodGet, "/v1/clients", nil, nil, "admin:read")
	if err != nil {
		return nil, err
	}

	var listResp ListClientsResponse
	if err := decodeJSON(resp, &listResp, http.StatusOK); err != nil {
		return nil, err
	}

	return &listResp, nil
}

// DeleteClient deletes an OAuth2 client by ID.
// Requires: admin:write scope
// Automatically refreshes the access token if expired.
func (s *Session) DeleteClient(ctx context.Context, clientID string) error {
	resp, err := s.doAuthRequest(
		ctx,
		http.MethodDelete,
		"/v1/clients/"+clientID,
		nil,
		nil,
		"admin:write",
	)
	if err != nil {
		return err
	}

	return checkStatusNoContent(resp)
}
