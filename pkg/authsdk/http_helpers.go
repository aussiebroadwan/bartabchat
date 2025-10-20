package authsdk

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// url builds a complete URL by appending the path to the base URL.
func (c *SDKClient) url(path string) string {
	return c.BaseURL + path
}

// doRequest performs an HTTP request with the SDKClient's HTTP client.
// This is for unauthenticated requests (no Authorization header).
func (c *SDKClient) doRequest(
	ctx context.Context,
	method, path string,
	body io.Reader,
	headers map[string]string,
) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.url(path), body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set custom headers
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	return resp, nil
}

// doAuthRequest performs an authenticated HTTP request using the session's access token.
// It automatically checks scopes and refreshes the access token if needed.
func (s *Session) doAuthRequest(
	ctx context.Context,
	method, path string,
	body io.Reader,
	headers map[string]string,
	requiredScopes ...string,
) (*http.Response, error) {
	// Check scopes if required
	if err := s.checkScopes(requiredScopes...); err != nil {
		return nil, err
	}

	// Get a valid access token (auto-refresh if expired)
	token, err := s.getValidToken(ctx)
	if err != nil {
		return nil, err
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, method, s.client.url(path), body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set Authorization header
	req.Header.Set("Authorization", "Bearer "+token)

	// Set additional headers
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	// Execute request
	resp, err := s.client.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	return resp, nil
}

// decodeJSON decodes a JSON response into the target interface.
// Returns a typed OAuth2Error or MFARequiredError if the response indicates an error.
// Returns an error if decoding fails.
func decodeJSON(resp *http.Response, target any, expectedStatus int) error {
	defer resp.Body.Close()

	// Read body once for both error parsing and success decoding
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	// Check for error responses (non-2xx status codes)
	if resp.StatusCode != expectedStatus {
		return parseErrorResponse(resp, bodyBytes)
	}

	// Decode successful response
	if err := json.Unmarshal(bodyBytes, target); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	return nil
}

// checkStatusNoContent returns a typed error if the response status is not 204 No Content.
func checkStatusNoContent(resp *http.Response) error {
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return parseErrorResponse(resp, bodyBytes)
	}

	return nil
}
