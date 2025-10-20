package auth_test

import (
	"testing"

	"github.com/aussiebroadwan/bartab/pkg/authsdk"
	"github.com/stretchr/testify/require"
)

// TestIntrospectValidToken tests introspecting a valid access token.
// It verifies that all expected fields are present and correct.
func TestIntrospectValidToken(t *testing.T) {
	baseURL, cleanup := setupAuthContainer(t)
	defer cleanup()

	client := authsdk.NewSDKClient(baseURL)

	// Bootstrap and login
	clientID, clientSecret, adminUserID := bootstrapService(t, client)
	session := performLogin(t, client, clientID, clientSecret, adminUsername, adminPassword)

	// Introspect the token
	accessToken := session.AccessToken()
	introspection, err := session.IntrospectToken(t.Context(), accessToken)
	require.NoError(t, err)
	require.NotNil(t, introspection)

	// Verify the token is active
	require.True(t, introspection.Active, "Token should be active")

	// Verify basic fields
	require.Equal(t, "Bearer", introspection.TokenType)
	require.NotEmpty(t, introspection.Scope, "Scope should not be empty")
	require.Equal(t, adminUserID, introspection.Sub, "Subject should match user ID")
	require.Equal(t, adminUsername, introspection.Username, "Username should match")
	require.Equal(t, adminPreferredName, introspection.PreferredName, "Preferred name should match")

	// Verify audience contains the client ID
	require.NotEmpty(t, introspection.Aud, "Audience should not be empty")
	require.Contains(t, introspection.Aud, clientID, "Audience should contain client ID")
	require.Equal(t, clientID, introspection.ClientID, "Client ID should match first audience")

	// Verify issuer
	require.Equal(t, "bartab-auth", introspection.Iss, "Issuer should match")

	// Verify timestamps are present
	require.NotZero(t, introspection.Exp, "Expiry timestamp should be set")
	require.NotZero(t, introspection.Iat, "Issued at timestamp should be set")
	require.NotZero(t, introspection.Nbf, "Not before timestamp should be set")

	// Verify JTI and session ID
	require.NotEmpty(t, introspection.Jti, "JTI should not be empty")
	require.NotEmpty(t, introspection.SessionID, "Session ID should not be empty")

	// Verify AMR (authentication method reference) contains password
	require.Contains(t, introspection.AMR, "pwd", "AMR should contain 'pwd'")

	// Verify expiry is in the future
	require.Greater(t, introspection.Exp, introspection.Iat, "Expiry should be after issuance")

	t.Logf("Introspection successful [Active]")
	t.Logf("Subject: %s", introspection.Sub)
	t.Logf("Username: %s", introspection.Username)
	t.Logf("Scopes: %s", introspection.Scope)
}

// TestIntrospectInvalidToken tests introspecting a malformed/invalid token.
// Per RFC7662, the server should return {"active": false} without revealing why.
func TestIntrospectInvalidToken(t *testing.T) {
	baseURL, cleanup := setupAuthContainer(t)
	defer cleanup()

	client := authsdk.NewSDKClient(baseURL)

	// Bootstrap and login to get a valid access token for authentication
	clientID, clientSecret, _ := bootstrapService(t, client)
	session := performLogin(t, client, clientID, clientSecret, adminUsername, adminPassword)

	// Try to introspect a malformed token
	invalidToken := "not.a.valid.jwt.token"
	introspection, err := session.IntrospectToken(t.Context(), invalidToken)

	require.NoError(t, err, "Introspection should succeed (HTTP 200)")
	require.NotNil(t, introspection)

	// Verify the token is marked inactive
	require.False(t, introspection.Active, "Invalid token should be marked inactive")

	// Verify no additional fields are present (per RFC7662 recommendation)
	require.Empty(t, introspection.Scope, "Inactive response should not contain scope")
	require.Empty(t, introspection.Username, "Inactive response should not contain username")
	require.Zero(t, introspection.Exp, "Inactive response should not contain exp")

	t.Logf("Invalid token correctly marked [Inactive]")
}

// TestIntrospectWithoutAuthentication tests that the introspection endpoint
// requires authentication (bearer token).
func TestIntrospectWithoutAuthentication(t *testing.T) {
	baseURL, cleanup := setupAuthContainer(t)
	defer cleanup()

	client := authsdk.NewSDKClient(baseURL)

	// Try to introspect without providing authentication
	// Create an empty session with no access token
	emptySession := client.NewSessionFromTokens("client-id", "", "", "", 0)
	_, err := emptySession.IntrospectToken(t.Context(), "some.token.here")

	require.Error(t, err, "Introspection without authentication should fail")

	t.Logf("Introspection correctly requires authentication")
}

// TestIntrospectOtherUsersToken tests that a user can introspect another user's token.
// This is the expected behavior - the introspection endpoint is for service-to-service
// token validation, not for privacy protection.
func TestIntrospectOtherUsersToken(t *testing.T) {
	baseURL, cleanup := setupAuthContainer(t)
	defer cleanup()

	client := authsdk.NewSDKClient(baseURL)

	// Bootstrap and create two users
	clientID, clientSecret, _ := bootstrapService(t, client)
	adminSession := performLogin(t, client, clientID, clientSecret, adminUsername, adminPassword)

	// Create an invite and redeem it to create a second user
	userRoleID := findRoleByName(t, adminSession, "user")
	inviteResp := createInvite(t, adminSession, clientID, userRoleID, false)
	redeemInvite(t, client, inviteResp.InviteToken, "normaluser", "User123!", clientID)

	// Login as the normal user
	userSession := performLogin(t, client, clientID, clientSecret, "normaluser", "User123!")

	// Use admin's token to introspect the normal user's token
	userAccessToken := userSession.AccessToken()
	introspection, err := adminSession.IntrospectToken(t.Context(), userAccessToken)

	require.NoError(t, err)
	require.NotNil(t, introspection)

	// Verify the token is active and belongs to the normal user
	require.True(t, introspection.Active, "Token should be active")
	require.Equal(t, "normaluser", introspection.Username, "Should see the other user's username")

	t.Logf("Introspection successful [Active]")
	t.Logf("Subject: %s", introspection.Sub)
	t.Logf("Username: %s", introspection.Username)
}
