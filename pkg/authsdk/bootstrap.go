package authsdk

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// Bootstrap initializes the auth service with an admin user and client.
func (c *SDKClient) Bootstrap(
	ctx context.Context,
	token string,
	req BootstrapRequest,
) (*BootstrapResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		c.BaseURL+"/v1/bootstrap",
		bytes.NewReader(body),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-Bootstrap-Token", token)

	resp, err := c.HTTPClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf(
			"bootstrap failed with status %d: %s",
			resp.StatusCode,
			string(bodyBytes),
		)
	}

	var bootstrapResp BootstrapResponse
	if err := json.NewDecoder(resp.Body).Decode(&bootstrapResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &bootstrapResp, nil
}
