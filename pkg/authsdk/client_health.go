package authsdk

import (
	"context"
	"net/http"
)

// GetLiveness checks if the service is alive.
func (c *SDKClient) GetLiveness(ctx context.Context) (*HealthResponse, error) {
	resp, err := c.doRequest(ctx, http.MethodGet, "/livez", nil, nil)
	if err != nil {
		return nil, err
	}

	var health HealthResponse
	if err := decodeJSON(resp, &health, http.StatusOK); err != nil {
		return nil, err
	}

	return &health, nil
}

// GetReadiness checks if the service is ready.
func (c *SDKClient) GetReadiness(ctx context.Context) (*HealthResponse, error) {
	resp, err := c.doRequest(ctx, http.MethodGet, "/readyz", nil, nil)
	if err != nil {
		return nil, err
	}

	var health HealthResponse
	if err := decodeJSON(resp, &health, http.StatusOK); err != nil {
		return nil, err
	}

	return &health, nil
}
