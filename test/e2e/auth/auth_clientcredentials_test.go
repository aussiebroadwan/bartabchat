package auth_test

import (
	"testing"

	"github.com/aussiebroadwan/bartab/pkg/authsdk"
	"github.com/stretchr/testify/require"
)

// TestClientCredentialsFlow tests the complete client_credentials grant flow:
// 1. Bootstrap the service
// 2. Login with admin credentials
// 3. Create a confidential client (bot)
// 4. Bot authenticates using client_credentials grant
// 5. Bot uses token to introspect itself (validates token works)
func TestClientCredentialsFlow(t *testing.T) {
	client, _, adminSession := setupClientTest(t)

	// Create a confidential client (bot)
	botClientID, botClientSecret := createConfidentialClient(t, adminSession, "test_bot", []string{"profile:read", "admin:read"})

	// Bot authenticates using client_credentials grant
	botTokenResp := authenticateClient(t, client, botClientID, botClientSecret, []string{"profile:read", "admin:read"})
	require.Empty(t, botTokenResp.RefreshToken, "Client credentials should NOT return refresh token")
	require.Contains(t, botTokenResp.Scope, "profile:read")
	require.Contains(t, botTokenResp.Scope, "admin:read")

	t.Logf("Bot authenticated successfully using client_credentials")
	t.Logf("Token Scope: %s", botTokenResp.Scope)

	// Bot uses token to introspect itself (validates token works)
	// Create a session from the bot's token to use IntrospectToken
	botSession := client.NewSessionFromTokens(botClientID, botTokenResp.AccessToken, "", botTokenResp.Scope, botTokenResp.ExpiresIn)
	introspectResp, err := botSession.IntrospectToken(t.Context(), botTokenResp.AccessToken)
	require.NoError(t, err)
	require.NotNil(t, introspectResp)
	require.True(t, introspectResp.Active, "Bot token should be active")
	require.Equal(t, botClientID, introspectResp.Sub, "Subject should be bot client ID")
	require.Equal(t, botClientID, introspectResp.ClientID, "Client ID should match")
	require.Contains(t, introspectResp.Scope, "profile:read")
	require.Contains(t, introspectResp.Scope, "admin:read")
	require.Contains(t, introspectResp.AMR, "client", "AMR should include 'client' method")
	require.Equal(t, "test_bot", introspectResp.Username, "Username should be client name")

	t.Logf("Token introspection successful")
	t.Logf("Subject (client_id): %s", introspectResp.Sub)
	t.Logf("Username (client name): %s", introspectResp.Username)
}

// TestClientCredentialsPublicClientRejected verifies that public clients
// (those without secrets) cannot use client_credentials grant.
func TestClientCredentialsPublicClientRejected(t *testing.T) {
	client, _, adminSession := setupClientTest(t)

	// Create a PUBLIC client (no secret)
	publicClientID := createPublicClient(t, adminSession, "public_web_app", []string{"profile:read"})

	// Attempt client_credentials grant with public client (should fail)
	t.Logf("Attempting client_credentials with public client...")
	_, err := client.ClientCredentialsGrant(
		t.Context(),
		publicClientID,
		"fake-secret", // Public client has no secret
		[]string{"profile:read"},
	)

	require.Error(t, err, "Public client should not be able to use client_credentials")
	require.Contains(t, err.Error(), "401", "Should return 401 for invalid client")

	t.Logf("Public client correctly rejected from client_credentials grant")
}

// TestClientCredentialsWrongSecret verifies that incorrect secrets are rejected.
func TestClientCredentialsWrongSecret(t *testing.T) {
	client, _, adminSession := setupClientTest(t)

	// Create confidential client
	botClientID, _ := createConfidentialClient(t, adminSession, "bot_with_secret", []string{"profile:read"})

	// Attempt with wrong secret
	t.Logf("Attempting client_credentials with wrong secret...")
	_, err := client.ClientCredentialsGrant(
		t.Context(),
		botClientID,
		"wrong-secret-12345",
		[]string{"profile:read"},
	)

	require.Error(t, err, "Wrong secret should be rejected")
	require.Contains(t, err.Error(), "401", "Should return 401 for invalid credentials")

	t.Logf("Wrong secret correctly rejected")
}

// TestClientCredentialsScopeRestriction verifies that bots can only request
// scopes that their client is authorized for.
func TestClientCredentialsScopeRestriction(t *testing.T) {
	client, _, adminSession := setupClientTest(t)

	// Create bot with limited scopes (only profile:read)
	botClientID, botClientSecret := createConfidentialClient(t, adminSession, "limited_bot", []string{"profile:read"})
	t.Logf("Limited bot created (only profile:read scope)")

	// Test 1: Request unauthorized scope (should succeed but not grant unauthorized scope)
	t.Run("RequestUnauthorizedScope", func(t *testing.T) {
		t.Logf("Bot requesting profile:read + admin:write (only profile:read is authorized)...")
		tokenResp := authenticateClient(t, client, botClientID, botClientSecret, []string{"profile:read", "admin:write"})

		// Should only get profile:read (intersection of requested and allowed scopes)
		require.Contains(t, tokenResp.Scope, "profile:read", "Should grant authorized scope")
		assertScopeNotGranted(t, tokenResp.Scope, "admin:write")

		t.Logf("Bot received token with only authorized scope: %s", tokenResp.Scope)
		t.Logf("Unauthorized scope (admin:write) correctly NOT granted")
	})

	// Test 2: Request only authorized scope (should succeed)
	t.Run("RequestAuthorizedScope", func(t *testing.T) {
		t.Logf("Bot requesting only authorized scope (profile:read)...")
		tokenResp := authenticateClient(t, client, botClientID, botClientSecret, []string{"profile:read"})

		require.Equal(t, "profile:read", tokenResp.Scope, "Should only grant authorized scope")

		t.Logf("Bot successfully obtained token with authorized scope: %s", tokenResp.Scope)
	})
}

// TestClientCredentialsNoRefreshToken verifies that client_credentials
// does not issue refresh tokens (clients can re-authenticate anytime).
func TestClientCredentialsNoRefreshToken(t *testing.T) {
	client, _, adminSession := setupClientTest(t)

	// Create bot and authenticate
	botClientID, botClientSecret := createConfidentialClient(t, adminSession, "no_refresh_bot", []string{"profile:read"})
	tokenResp := authenticateClient(t, client, botClientID, botClientSecret, []string{"profile:read"})

	require.NotEmpty(t, tokenResp.AccessToken, "Should have access token")
	require.Empty(t, tokenResp.RefreshToken, "Should NOT have refresh token")

	t.Logf("Client credentials correctly omits refresh token")
}

// TestListClientsAndDelete tests the client management endpoints:
// 1. Create multiple clients (public and confidential)
// 2. List all clients
// 3. Attempt to delete protected bootstrap client (should fail)
// 4. Delete non-protected client (should succeed)
func TestListClientsAndDelete(t *testing.T) {
	_, bootstrapClientID, adminSession := setupClientTest(t)

	// Create multiple clients
	t.Logf("Creating multiple test clients...")
	publicClientID := createPublicClient(t, adminSession, "public_app", []string{"profile:read"})
	confClientID, _ := createConfidentialClient(t, adminSession, "confidential_bot", []string{"profile:read", "admin:read"})

	// List all clients
	t.Logf("Listing all clients...")
	listResp, err := adminSession.ListClients(t.Context())

	require.NoError(t, err)
	require.NotNil(t, listResp)
	require.GreaterOrEqual(t, len(listResp.Clients), 3, "Should have at least 3 clients (bootstrap + 2 created)")

	// Verify bootstrap client is marked as protected
	var foundBootstrap, foundPublic, foundConf bool
	for _, c := range listResp.Clients {
		t.Logf("Client: %s (name: %s, has_secret: %v, protected: %v)", c.ID, c.Name, c.HasSecret, c.Protected)

		if c.ID == bootstrapClientID {
			foundBootstrap = true

			require.True(t, c.Protected, "Bootstrap client should be protected")

			t.Logf("  Bootstrap client is protected")
		}
		if c.ID == publicClientID {
			foundPublic = true

			require.False(t, c.HasSecret, "Public client should not have secret")
			require.False(t, c.Protected, "New clients should not be protected")

			t.Logf("  Public client has no secret")
		}
		if c.ID == confClientID {
			foundConf = true

			require.True(t, c.HasSecret, "Confidential client should have secret")
			require.False(t, c.Protected, "New clients should not be protected")

			t.Logf("  Confidential client has secret")
		}
	}

	require.True(t, foundBootstrap, "Bootstrap client should be in list")
	require.True(t, foundPublic, "Public client should be in list")
	require.True(t, foundConf, "Confidential client should be in list")

	t.Logf("All clients found in list")

	// Attempt to delete protected bootstrap client (should fail)
	t.Run("DeleteProtectedClient", func(t *testing.T) {
		t.Logf("Attempting to delete protected bootstrap client...")
		err := adminSession.DeleteClient(t.Context(), bootstrapClientID)

		require.Error(t, err, "Should not be able to delete protected client")

		var oauth2Err *authsdk.OAuth2Error
		require.ErrorAs(t, err, &oauth2Err, "Should return OAuth2Error")
		// The server returns "client_protected" as a custom error code for protected clients
		require.Equal(t, "client_protected", oauth2Err.Code, "Should return client_protected error")
		require.Contains(t, oauth2Err.Description, "protected", "Error should mention client is protected")

		t.Logf("Protected client deletion correctly rejected")
	})

	// Delete non-protected public client (should succeed)
	t.Run("DeleteNonProtectedClient", func(t *testing.T) {
		t.Logf("Deleting non-protected public client: %s", publicClientID)
		err := adminSession.DeleteClient(t.Context(), publicClientID)

		require.NoError(t, err, "Should be able to delete non-protected client")

		t.Logf("Non-protected client deleted successfully")

		// Verify it's gone from the list
		listResp2, err := adminSession.ListClients(t.Context())

		require.NoError(t, err)
		for _, c := range listResp2.Clients {
			require.NotEqual(t, publicClientID, c.ID, "Deleted client should not be in list")
		}

		t.Logf("Verified deleted client is no longer in list")
	})
}

// ================================================
// Helper functions for client credentials tests
// ================================================

// setupClientTest is a helper that bootstraps the service, logs in as admin,
// and returns the client, bootstrap clientID, and admin session.
func setupClientTest(t *testing.T) (*authsdk.SDKClient, string, *authsdk.Session) {
	t.Helper()

	baseURL, cleanup := setupAuthContainer(t)
	t.Cleanup(cleanup)

	client := authsdk.NewSDKClient(baseURL)
	clientID, clientSecret, _ := bootstrapService(t, client)
	adminSession := performLogin(t, client, clientID, clientSecret, adminUsername, adminPassword)

	return client, clientID, adminSession
}

// createConfidentialClient is a helper that creates a confidential client with a secret.
// Returns the client ID and the auto-generated secret.
func createConfidentialClient(t *testing.T, session *authsdk.Session, name string, scopes []string) (clientID, clientSecret string) {
	t.Helper()

	createResp, err := session.CreateClient(t.Context(), authsdk.CreateClientRequest{
		Name:         name,
		Confidential: true,
		Scopes:       scopes,
	})

	require.NoError(t, err)
	require.NotNil(t, createResp)
	require.NotEmpty(t, createResp.ClientID, "Client ID should be returned")
	require.NotEmpty(t, createResp.ClientSecret, "Client secret should be auto-generated")

	t.Logf("Confidential client created: %s", createResp.ClientID)
	return createResp.ClientID, createResp.ClientSecret
}

// createPublicClient is a helper that creates a public client (no secret).
// Returns the client ID.
func createPublicClient(t *testing.T, session *authsdk.Session, name string, scopes []string) string {
	t.Helper()

	createResp, err := session.CreateClient(t.Context(), authsdk.CreateClientRequest{
		Name:         name,
		Confidential: false,
		Scopes:       scopes,
	})

	require.NoError(t, err)
	require.NotNil(t, createResp)
	require.NotEmpty(t, createResp.ClientID, "Client ID should be returned")
	require.Empty(t, createResp.ClientSecret, "Public client should not have a secret")

	t.Logf("Public client created: %s", createResp.ClientID)
	return createResp.ClientID
}

// authenticateClient is a helper that authenticates using client_credentials grant.
// Returns the token response.
func authenticateClient(t *testing.T, client *authsdk.SDKClient, clientID, clientSecret string, scopes []string) *authsdk.TokenResponse {
	t.Helper()

	tokenResp, err := client.ClientCredentialsGrant(t.Context(), clientID, clientSecret, scopes)

	require.NoError(t, err)
	require.NotNil(t, tokenResp)
	require.NotEmpty(t, tokenResp.AccessToken, "Access token should not be empty")
	require.Equal(t, "Bearer", tokenResp.TokenType, "Token type should be Bearer")

	return tokenResp
}
