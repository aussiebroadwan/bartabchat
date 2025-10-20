package authsdk

import (
	"context"
	"net/http"
	"strings"
	"time"
)

// SDKClient is a client for the BarTab authentication service.
// It provides access to unauthenticated operations and can create authenticated Sessions.
type SDKClient struct {
	BaseURL    string
	HTTPClient *http.Client

	// CheckScopes determines whether to perform client-side scope validation
	// before making API requests. When true, the Session will check if it has
	// the required scopes before making a request and return an error if not.
	// This avoids unnecessary API calls and provides better error messages.
	// Set to false for testing to ensure server-side scope checks work correctly.
	// Default: true
	CheckScopes bool
}

// NewSDKClient creates a new auth service client with scope checking enabled.
func NewSDKClient(baseURL string) *SDKClient {
	return &SDKClient{
		BaseURL: strings.TrimSuffix(baseURL, "/"),
		HTTPClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		CheckScopes: true, // Enabled by default
	}
}

// AuthenticateWithClientCredentials creates an authenticated session using client credentials grant.
// This is for machine-to-machine (M2M) authentication.
func (c *SDKClient) AuthenticateWithClientCredentials(
	ctx context.Context,
	clientID, clientSecret string,
	scopes []string,
) (*Session, error) {
	tokenResp, err := c.ClientCredentialsGrant(ctx, clientID, clientSecret, scopes)
	if err != nil {
		return nil, err
	}

	return newSession(c, clientID, tokenResp), nil
}

// AuthenticateWithRefreshToken creates an authenticated session from an existing refresh token.
func (c *SDKClient) AuthenticateWithRefreshToken(
	ctx context.Context,
	clientID, refreshToken string,
) (*Session, error) {
	tokenResp, err := c.RefreshGrant(ctx, clientID, refreshToken)
	if err != nil {
		return nil, err
	}

	return newSession(c, clientID, tokenResp), nil
}

// NewSessionFromTokens creates an authenticated session from existing tokens.
// This is useful when you already have tokens from a previous authentication
// (e.g., stored in a database or passed from another system).
// The session will still perform auto-refresh when the access token expires.
func (c *SDKClient) NewSessionFromTokens(clientID, accessToken, refreshToken, scope string, expiresIn int) *Session {
	expiresAt := time.Now().Add(time.Duration(expiresIn) * time.Second)
	expiresAt = expiresAt.Add(-30 * time.Second) // 30 second buffer

	return &Session{
		client:       c,
		clientID:     clientID,
		accessToken:  accessToken,
		refreshToken: refreshToken,
		expiresAt:    expiresAt,
		scopes:       parseScopes(scope),
	}
}
