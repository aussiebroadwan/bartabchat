package auth_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/aussiebroadwan/bartab/pkg/authsdk"
	"github.com/stretchr/testify/require"
)

// TestAuthorizeGETWithoutSession tests the GET endpoint without a session.
// This is the typical first step in a browser-based OAuth2 flow where the user
// hasn't logged in yet.
func TestAuthorizeGETWithoutSession(t *testing.T) {
	baseURL, cleanup := setupAuthContainer(t)
	defer cleanup()

	client := authsdk.NewSDKClient(baseURL)
	clientID, _, _ := bootstrapService(t, client)

	// Build authorization URL
	redirectURI := "https://example.com/callback"
	state := "random-state-123"
	scopes := []string{"profile:read", "admin:write"}
	pkce, err := authsdk.GeneratePKCEChallenge()
	require.NoError(t, err)

	authURL := client.BuildAuthorizeURL(clientID, redirectURI, state, scopes, pkce)

	t.Logf("Authorization URL: %s", authURL)

	// Make GET request without session (no cookie, no Bearer token)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, authURL, nil)
	require.NoError(t, err)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Should return 401 with login_required error
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode, "Should return 401 when no session exists")

	// Parse response body
	var errorResp struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
		ResponseType     string `json:"response_type"`
		ClientID         string `json:"client_id"`
		RedirectURI      string `json:"redirect_uri"`
		Scope            string `json:"scope"`
		State            string `json:"state"`
	}
	err = json.NewDecoder(resp.Body).Decode(&errorResp)
	require.NoError(t, err)

	require.Equal(t, "login_required", errorResp.Error)
	require.Equal(t, "user authentication required", errorResp.ErrorDescription)
	require.Equal(t, "code", errorResp.ResponseType)
	require.Equal(t, clientID, errorResp.ClientID)
	require.Equal(t, redirectURI, errorResp.RedirectURI)
	require.Contains(t, errorResp.Scope, "profile:read")
	require.Equal(t, state, errorResp.State)

	t.Logf("GET without session correctly returned login_required error")
}

// TestAuthorizeGETWithBearerToken tests the GET endpoint with a Bearer token.
// This simulates a browser-based flow where the user has already logged in
// and has a valid access token (perhaps stored in localStorage).
func TestAuthorizeGETWithBearerToken(t *testing.T) {
	baseURL, cleanup := setupAuthContainer(t)
	defer cleanup()

	client := authsdk.NewSDKClient(baseURL)
	clientID, clientSecret, _ := bootstrapService(t, client)

	redirectURI := "https://example.com/callback"

	// Step 1: Get an initial session (simulating prior login)
	initialScopes := []string{"profile:read", "profile:write", "admin:read", "admin:write"}
	initialSession, err := client.AuthorizeAndExchange(
		t.Context(),
		clientID,
		clientSecret,
		redirectURI,
		adminUsername,
		adminPassword,
		initialScopes,
	)
	require.NoError(t, err)
	require.NotNil(t, initialSession)

	t.Logf("Initial session obtained, access token: %s...", initialSession.AccessToken()[:20])

	// Step 2: Use redirect with Bearer token to authorize with different scopes
	newScopes := []string{"profile:read", "admin:write"}
	newSession, err := client.AuthorizeAndExchangeViaRedirect(
		t.Context(),
		initialSession.AccessToken(), // Use access token
		"",                            // No cookie
		clientID,
		clientSecret,
		redirectURI,
		newScopes,
	)
	require.NoError(t, err)
	require.NotNil(t, newSession)

	t.Logf("Successfully completed GET authorization with Bearer token")

	// Verify new token has expected scopes
	introspect, err := newSession.IntrospectToken(t.Context(), newSession.AccessToken())
	require.NoError(t, err)
	require.Contains(t, introspect.Scope, "profile:read")
	require.Contains(t, introspect.Scope, "admin:write")

	t.Logf("GET with Bearer token successfully completed authorization code flow")
}

// TestAuthorizeGETWithCookie tests the GET endpoint with a session cookie.
// This simulates a traditional browser-based OAuth2 flow where the user's
// session is maintained via HTTP cookies.
func TestAuthorizeGETWithCookie(t *testing.T) {
	baseURL, cleanup := setupAuthContainer(t)
	defer cleanup()

	client := authsdk.NewSDKClient(baseURL)
	clientID, clientSecret, _ := bootstrapService(t, client)

	redirectURI := "https://example.com/callback"

	// Step 1: Get an initial session (simulating prior login)
	initialScopes := []string{"profile:read", "profile:write", "admin:read", "admin:write"}
	initialSession, err := client.AuthorizeAndExchange(
		t.Context(),
		clientID,
		clientSecret,
		redirectURI,
		adminUsername,
		adminPassword,
		initialScopes,
	)
	require.NoError(t, err)
	require.NotNil(t, initialSession)

	t.Logf("Initial session obtained")

	// Step 2: Use redirect with session cookie to authorize with different scopes
	// In a real browser flow, the cookie would be set by the server and included automatically
	newScopes := []string{"profile:read"}
	newSession, err := client.AuthorizeAndExchangeViaRedirect(
		t.Context(),
		"",                            // No Bearer token
		initialSession.AccessToken(), // Use as cookie value
		clientID,
		clientSecret,
		redirectURI,
		newScopes,
	)
	require.NoError(t, err)
	require.NotNil(t, newSession)

	t.Logf("Successfully completed GET authorization with session cookie")

	// Verify new token has expected scopes
	introspect, err := newSession.IntrospectToken(t.Context(), newSession.AccessToken())
	require.NoError(t, err)
	require.Contains(t, introspect.Scope, "profile:read")

	t.Logf("GET with session cookie successfully completed authorization code flow")
}

// TestAuthorizeGETWithInvalidToken tests the GET endpoint with an invalid Bearer token.
// This simulates a scenario where the user's token has expired or is malformed.
func TestAuthorizeGETWithInvalidToken(t *testing.T) {
	baseURL, cleanup := setupAuthContainer(t)
	defer cleanup()

	client := authsdk.NewSDKClient(baseURL)
	clientID, clientSecret, _ := bootstrapService(t, client)

	redirectURI := "https://example.com/callback"
	scopes := []string{"profile:read"}

	// Try to authorize with an invalid token
	_, err := client.AuthorizeAndExchangeViaRedirect(
		t.Context(),
		"invalid-token-12345", // Invalid Bearer token
		"",                    // No cookie
		clientID,
		clientSecret,
		redirectURI,
		scopes,
	)
	require.Error(t, err, "Should fail with invalid token")
	require.Contains(t, err.Error(), "authentication required", "Error should indicate authentication is required")

	t.Logf("GET with invalid token correctly returned error: %v", err)
}
