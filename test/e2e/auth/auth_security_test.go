package auth_test

import (
	"testing"

	"github.com/aussiebroadwan/bartab/pkg/authsdk"
)

// TestInvalidCredentials verifies that login with wrong password is rejected.
func TestInvalidCredentials(t *testing.T) {
	baseURL, cleanup := setupAuthContainer(t)
	defer cleanup()

	client := authsdk.NewSDKClient(baseURL)

	// Bootstrap
	clientID, _, adminUserID := bootstrapService(t, client)

	t.Logf("Bootstrap successful")
	t.Logf("Admin User ID: %s", adminUserID)
	t.Logf("Client ID: %s", clientID)

	// Attempt login with wrong password using authorization code flow
	pkce, err := authsdk.GeneratePKCEChallenge()
	if err != nil {
		t.Fatalf("Failed to generate PKCE: %v", err)
	}

	_, err = client.AuthorizeWithPassword(t.Context(), clientID, "http://localhost/callback", adminUsername, "wrong-password", clientScopes, pkce)
	assertUnauthorized(t, err, "Invalid password should be rejected")

	t.Logf("Invalid credentials correctly rejected with 401")
}

// TestInvalidAccessToken verifies that userinfo endpoint rejects invalid tokens.
func TestInvalidAccessToken(t *testing.T) {
	baseURL, cleanup := setupAuthContainer(t)
	defer cleanup()

	client := authsdk.NewSDKClient(baseURL)

	// Bootstrap (needed to initialize the service)
	clientID, _, adminUserID := bootstrapService(t, client)
	t.Logf("Bootstrap successful")
	t.Logf("Admin User ID: %s", adminUserID)
	t.Logf("Client ID: %s", clientID)

	// Attempt to use userinfo with invalid token
	// Create a session with invalid token to test server-side validation
	invalidSession := client.NewSessionFromTokens(
		clientID,
		"invalid-token-12345", // Invalid access token
		"",                    // No refresh token
		"profile:read",
		3600,
	)

	_, err := invalidSession.GetUserInfo(t.Context())
	assertUnauthorized(t, err, "Invalid token should be rejected")

	t.Logf("Invalid token correctly rejected with 401")
}
