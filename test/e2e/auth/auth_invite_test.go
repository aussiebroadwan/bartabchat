package auth_test

import (
	"testing"
	"time"

	"github.com/aussiebroadwan/bartab/pkg/authsdk"
	"github.com/stretchr/testify/require"
)

// TestBootstrapLoginMintInvite tests the complete flow:
// 1. Bootstrap the service
// 2. Login with password grant
// 3. List available roles
// 4. Mint an invite token for the "user" role
func TestBootstrapLoginMintInvite(t *testing.T) {
	baseURL, cleanup := setupAuthContainer(t)
	defer cleanup()

	client := authsdk.NewSDKClient(baseURL)

	// Bootstrap
	clientID, clientSecret, adminUserID := bootstrapService(t, client)

	t.Logf("Bootstrap successful")
	t.Logf("Admin User ID: %s", adminUserID)
	t.Logf("Client ID: %s", clientID)

	// Login
	session := performLogin(t, client, clientID, clientSecret, adminUsername, adminPassword)

	t.Logf("Password grant successful")
	t.Logf("Access Token: %s", session.AccessToken())

	// Find the "user" role
	userRoleID := findRoleByName(t, session, "user")

	t.Logf("Found 'user' role (ID: %s)", userRoleID)

	// Mint invite token
	inviteResp, err := session.MintInvite(t.Context(), authsdk.InviteRequest{
		ClientID: clientID,
		RoleID:   userRoleID,
		Reusable: false,
	})

	require.NoError(t, err)
	require.NotNil(t, inviteResp)
	require.NotEmpty(t, inviteResp.InviteToken, "Invite token should be generated")
	require.Equal(t, clientID, inviteResp.ClientID, "Client ID should match")
	require.NotZero(t, inviteResp.ExpiresAt, "Expiry should be set")

	expiresAt := time.Unix(inviteResp.ExpiresAt, 0)
	t.Logf("Invite token created successfully!")
	t.Logf("Invite Token: %s", inviteResp.InviteToken)
	t.Logf("Expires At: %s", expiresAt.Format(time.RFC3339))
	t.Logf("Role ID: %s", userRoleID)
}

// TestInviteRedeemAndUserInfo tests the complete invite redemption flow:
// 1. Bootstrap the service
// 2. Login with admin credentials
// 3. Create an invite for the "user" role
// 4. Redeem the invite to create a new user
// 5. Login as the new user
// 6. Get user info for the new user
func TestInviteRedeemAndUserInfo(t *testing.T) {
	baseURL, cleanup := setupAuthContainer(t)
	defer cleanup()

	client := authsdk.NewSDKClient(baseURL)

	// Step 1: Bootstrap the service
	clientID, clientSecret, adminUserID := bootstrapService(t, client)

	t.Logf("Bootstrap successful")
	t.Logf("Admin User ID: %s", adminUserID)
	t.Logf("Client ID: %s", clientID)

	// Step 2: Login with admin credentials
	adminSession := performLogin(t, client, clientID, clientSecret, adminUsername, adminPassword)

	t.Logf("Admin login successful")

	// Step 3: Find the "user" role and create an invite
	userRoleID := findRoleByName(t, adminSession, "user")

	t.Logf("Found 'user' role (ID: %s)", userRoleID)

	inviteResp, err := adminSession.MintInvite(t.Context(), authsdk.InviteRequest{
		ClientID: clientID,
		RoleID:   userRoleID,
		Reusable: false,
	})

	require.NoError(t, err)
	require.NotNil(t, inviteResp)
	require.NotEmpty(t, inviteResp.InviteToken)

	t.Logf("Invite created successfully")
	t.Logf("Invite Token: %s", inviteResp.InviteToken)

	// Step 4: Redeem the invite to create a new user
	newUsername := "testuser"
	newPassword := "TestUser123!"

	redeemResp, err := client.RedeemInvite(t.Context(), authsdk.RedeemInviteRequest{
		InviteToken: inviteResp.InviteToken,
		Username:    newUsername,
		Password:    newPassword,
		ClientID:    clientID,
	})

	require.NoError(t, err)
	require.NotNil(t, redeemResp)
	require.NotEmpty(t, redeemResp.UserID, "User ID should be returned")
	require.Equal(t, newUsername, redeemResp.Username, "Username should match")

	t.Logf("Invite redeemed successfully")
	t.Logf("New User ID: %s", redeemResp.UserID)
	t.Logf("Username: %s", redeemResp.Username)

	// Step 5: Login as the new user
	newUserSession := performLogin(t, client, clientID, clientSecret, newUsername, newPassword)

	t.Logf("New user login successful")
	t.Logf("New User Access Token: %s", newUserSession.AccessToken())

	// Step 6: Get user info for the new user
	userInfo, err := newUserSession.GetUserInfo(t.Context())
	require.NoError(t, err)
	require.NotNil(t, userInfo)
	require.Equal(t, redeemResp.UserID, userInfo.UserID, "User ID should match")
	require.Equal(t, newUsername, userInfo.Username, "Username should match")
	require.Equal(t, newUsername, userInfo.PreferredName, "Preferred name should default to username")
	require.Equal(t, "user", userInfo.Role, "Role name should be 'user'")

	t.Logf("User info retrieved successfully")
	t.Logf("User ID: %s", userInfo.UserID)
	t.Logf("Username: %s", userInfo.Username)
	t.Logf("Preferred Name: %s", userInfo.PreferredName)
	t.Logf("Role: %s", userInfo.Role)

	// Verify that the invite cannot be reused (it was not reusable)
	t.Logf("Testing that non-reusable invite cannot be used again")

	_, err = client.RedeemInvite(t.Context(), authsdk.RedeemInviteRequest{
		InviteToken: inviteResp.InviteToken,
		Username:    "anotheruser",
		Password:    "AnotherUser123!",
		ClientID:    clientID,
	})

	require.Error(t, err, "Redeeming non-reusable invite twice should fail")

	// Check for OAuth2Error with invalid_grant code
	var oauth2Err *authsdk.OAuth2Error
	require.ErrorAs(t, err, &oauth2Err, "Should return OAuth2Error")
	require.Equal(t, authsdk.ErrorCodeInvalidGrant, oauth2Err.Code, "Should return invalid_grant error")

	t.Logf("Non-reusable invite correctly rejected on second use")
}

// TestRedeemInviteValidation tests various validation scenarios for invite redemption.
func TestRedeemInviteValidation(t *testing.T) {
	client, clientID, _, adminSession, userRoleID := setupInviteTest(t, "user")

	// Create a valid invite for testing
	inviteResp := createInvite(t, adminSession, clientID, userRoleID, false)

	// Test case: Invalid invite token
	t.Run("InvalidInviteToken", func(t *testing.T) {
		_, err := client.RedeemInvite(t.Context(), authsdk.RedeemInviteRequest{
			InviteToken: "invalid-token",
			Username:    "testuser1",
			Password:    "TestUser123!",
			ClientID:    clientID,
		})

		require.Error(t, err)

		var oauth2Err *authsdk.OAuth2Error
		require.ErrorAs(t, err, &oauth2Err, "Should return OAuth2Error")
		require.Equal(t, authsdk.ErrorCodeInvalidGrant, oauth2Err.Code, "Should return invalid_grant error")

		t.Logf("Invalid invite token correctly rejected")
	})

	// Test case: Missing username
	t.Run("MissingUsername", func(t *testing.T) {
		_, err := client.RedeemInvite(t.Context(), authsdk.RedeemInviteRequest{
			InviteToken: inviteResp.InviteToken,
			Username:    "",
			Password:    "TestUser123!",
			ClientID:    clientID,
		})

		require.Error(t, err)

		var oauth2Err *authsdk.OAuth2Error
		require.ErrorAs(t, err, &oauth2Err, "Should return OAuth2Error")
		require.Equal(t, authsdk.ErrorCodeInvalidRequest, oauth2Err.Code, "Should return invalid_request error")

		t.Logf("Missing username correctly rejected")
	})

	// Test case: Missing password
	t.Run("MissingPassword", func(t *testing.T) {
		_, err := client.RedeemInvite(t.Context(), authsdk.RedeemInviteRequest{
			InviteToken: inviteResp.InviteToken,
			Username:    "testuser2",
			Password:    "",
			ClientID:    clientID,
		})

		require.Error(t, err)

		var oauth2Err *authsdk.OAuth2Error
		require.ErrorAs(t, err, &oauth2Err, "Should return OAuth2Error")
		require.Equal(t, authsdk.ErrorCodeInvalidRequest, oauth2Err.Code, "Should return invalid_request error")

		t.Logf("Missing password correctly rejected")
	})

	// Test case: Wrong client ID
	t.Run("WrongClientID", func(t *testing.T) {
		_, err := client.RedeemInvite(t.Context(), authsdk.RedeemInviteRequest{
			InviteToken: inviteResp.InviteToken,
			Username:    "testuser3",
			Password:    "TestUser123!",
			ClientID:    "wrong-client-id",
		})

		require.Error(t, err)

		var oauth2Err *authsdk.OAuth2Error
		require.ErrorAs(t, err, &oauth2Err, "Should return OAuth2Error")
		require.Equal(t, authsdk.ErrorCodeInvalidGrant, oauth2Err.Code, "Should return invalid_grant error")

		t.Logf("Wrong client ID correctly rejected")
	})

	// Test case: Successfully redeem a valid invite
	t.Run("SuccessfulRedemption", func(t *testing.T) {
		redeemResp := redeemInvite(t, client, inviteResp.InviteToken, "validuser", "ValidUser123!", clientID)
		t.Logf("Successfully redeemed invite for user: %s", redeemResp.UserID)
	})

	// Test case: Duplicate username
	t.Run("DuplicateUsername", func(t *testing.T) {
		// Create another invite
		inviteResp2 := createInvite(t, adminSession, clientID, userRoleID, false)

		// Try to create user with already-taken username
		_, err := client.RedeemInvite(t.Context(), authsdk.RedeemInviteRequest{
			InviteToken: inviteResp2.InviteToken,
			Username:    "validuser", // Already exists from previous test
			Password:    "AnotherPassword123!",
			ClientID:    clientID,
		})

		require.Error(t, err)

		var oauth2Err *authsdk.OAuth2Error
		require.ErrorAs(t, err, &oauth2Err, "Should return OAuth2Error")
		require.Equal(t, authsdk.ErrorCodeInvalidRequest, oauth2Err.Code, "Should return invalid_request error")
		require.Contains(t, oauth2Err.Description, "already taken", "Error should mention username is taken")

		t.Logf("Duplicate username correctly rejected")
	})
}

// TestReusableInvite tests that reusable invites can be used multiple times.
func TestReusableInvite(t *testing.T) {
	client, clientID, clientSecret, adminSession, userRoleID := setupInviteTest(t, "user")

	// Create a reusable invite
	inviteResp := createInvite(t, adminSession, clientID, userRoleID, true)

	t.Logf("Reusable invite created: %s", inviteResp.InviteToken)

	// Redeem the invite for the first user
	redeemResp1 := redeemInvite(t, client, inviteResp.InviteToken, "reusableuser1", "ReusableUser1!", clientID)

	t.Logf("First user created: %s", redeemResp1.UserID)

	// Redeem the same invite for the second user (should succeed because it's reusable)
	redeemResp2 := redeemInvite(t, client, inviteResp.InviteToken, "reusableuser2", "ReusableUser2!", clientID)

	require.NotEqual(t, redeemResp1.UserID, redeemResp2.UserID, "User IDs should be different")

	t.Logf("Second user created: %s", redeemResp2.UserID)

	// Verify both users can login using authorization code flow
	accessToken1, err := client.AuthorizeAndExchange(t.Context(), clientID, clientSecret, "http://localhost/callback", "reusableuser1", "ReusableUser1!", []string{"profile:read"})

	require.NoError(t, err)

	t.Logf("First user can login")
	t.Logf("Access Token First User: %s", accessToken1.AccessToken())

	accessToken2, err := client.AuthorizeAndExchange(t.Context(), clientID, clientSecret, "http://localhost/callback", "reusableuser2", "ReusableUser2!", []string{"profile:read"})

	require.NoError(t, err)

	t.Logf("Second user can login")
	t.Logf("Access Token Second User: %s", accessToken2.AccessToken())
}

// TestInviteUserScopeRestriction tests that a user created with "user" role
// cannot obtain admin scopes even if they request them during login.
func TestInviteUserScopeRestriction(t *testing.T) {
	client, clientID, clientSecret, adminSession, userRoleID := setupInviteTest(t, "user")
	t.Logf("Found 'user' role (ID: %s)", userRoleID)

	// Create an invite for the "user" role
	inviteResp := createInvite(t, adminSession, clientID, userRoleID, false)
	t.Logf("Invite created for 'user' role")

	// Redeem the invite to create a regular user
	newUsername := "regularuser"
	newPassword := "RegularUser123!"
	redeemResp := redeemInvite(t, client, inviteResp.InviteToken, newUsername, newPassword, clientID)
	t.Logf("User created: %s (ID: %s)", redeemResp.Username, redeemResp.UserID)

	// Test 1: Login requesting only allowed scopes (should succeed)
	// Note: The client only has profile:read (not profile:write), so that's all the user can get
	t.Run("AllowedScopes", func(t *testing.T) {
		pkce, err := authsdk.GeneratePKCEChallenge()
		require.NoError(t, err)

		code, err := client.AuthorizeWithPassword(t.Context(), clientID, "http://localhost/callback", newUsername, newPassword, []string{"profile:read"}, pkce)
		require.NoError(t, err)

		tokenResp, err := client.ExchangeAuthorizationCode(t.Context(), clientID, clientSecret, code, "http://localhost/callback", pkce.Verifier)
		require.NoError(t, err)
		require.NotEmpty(t, tokenResp.AccessToken)
		require.Contains(t, tokenResp.Scope, "profile:read")

		t.Logf("User can login with allowed scopes: %s", tokenResp.Scope)
	})

	// Test 2: Login requesting admin scopes (should succeed but NOT grant admin scopes)
	t.Run("RequestAdminScopes", func(t *testing.T) {
		pkce, err := authsdk.GeneratePKCEChallenge()
		require.NoError(t, err)

		code, err := client.AuthorizeWithPassword(t.Context(), clientID, "http://localhost/callback", newUsername, newPassword, []string{"profile:read", "admin:read", "admin:write"}, pkce)
		require.NoError(t, err)

		tokenResp, err := client.ExchangeAuthorizationCode(t.Context(), clientID, clientSecret, code, "http://localhost/callback", pkce.Verifier)
		require.NoError(t, err)
		require.NotEmpty(t, tokenResp.AccessToken)

		// Should only get profile:read (intersection of requested and allowed scopes)
		require.Contains(t, tokenResp.Scope, "profile:read")
		assertScopeNotGranted(t, tokenResp.Scope, "admin:read", "admin:write")

		t.Logf("User requested admin scopes but only got: %s", tokenResp.Scope)
	})

	// Test 3: Verify user cannot access admin endpoints
	t.Run("CannotAccessAdminEndpoints", func(t *testing.T) {
		pkce, err := authsdk.GeneratePKCEChallenge()
		require.NoError(t, err)

		code, err := client.AuthorizeWithPassword(t.Context(), clientID, "http://localhost/callback", newUsername, newPassword, []string{"profile:read"}, pkce)
		require.NoError(t, err)

		tokenResp, err := client.ExchangeAuthorizationCode(t.Context(), clientID, clientSecret, code, "http://localhost/callback", pkce.Verifier)
		require.NoError(t, err)

		// Create a session from the token response
		userSession := client.NewSessionFromTokens(clientID, tokenResp.AccessToken, tokenResp.RefreshToken, tokenResp.Scope, tokenResp.ExpiresIn)

		// Try to list roles (requires admin:read scope)
		_, err = userSession.ListRoles(t.Context())

		assertCannotAccessEndpoint(t, err, "User without admin:read should not be able to list roles")

		t.Logf("User correctly denied access to admin endpoint")
	})

	// Test 4: Verify user cannot mint invites
	t.Run("CannotMintInvites", func(t *testing.T) {
		pkce, err := authsdk.GeneratePKCEChallenge()
		require.NoError(t, err)

		code, err := client.AuthorizeWithPassword(t.Context(), clientID, "http://localhost/callback", newUsername, newPassword, []string{"profile:read"}, pkce)
		require.NoError(t, err)

		tokenResp, err := client.ExchangeAuthorizationCode(t.Context(), clientID, clientSecret, code, "http://localhost/callback", pkce.Verifier)
		require.NoError(t, err)

		// Create a session from the token response
		userSession := client.NewSessionFromTokens(clientID, tokenResp.AccessToken, tokenResp.RefreshToken, tokenResp.Scope, tokenResp.ExpiresIn)

		// Try to mint an invite (requires admin:write scope)
		_, err = userSession.MintInvite(t.Context(), authsdk.InviteRequest{
			ClientID: clientID,
			RoleID:   userRoleID,
			Reusable: false,
		})

		assertCannotAccessEndpoint(t, err, "User without admin:write should not be able to mint invites")

		t.Logf("User correctly denied ability to mint invites")
	})

	// Test 5: Verify admin can still access everything
	t.Run("AdminCanAccessEverything", func(t *testing.T) {
		pkce, err := authsdk.GeneratePKCEChallenge()
		require.NoError(t, err)

		code, err := client.AuthorizeWithPassword(t.Context(), clientID, "http://localhost/callback", adminUsername, adminPassword, []string{"profile:read", "admin:read", "admin:write"}, pkce)
		require.NoError(t, err)

		adminTokenResp, err := client.ExchangeAuthorizationCode(t.Context(), clientID, clientSecret, code, "http://localhost/callback", pkce.Verifier)
		require.NoError(t, err)
		require.Contains(t, adminTokenResp.Scope, "admin:read")
		require.Contains(t, adminTokenResp.Scope, "admin:write")

		// Create a session from the token response
		adminSession := client.NewSessionFromTokens(clientID, adminTokenResp.AccessToken, adminTokenResp.RefreshToken, adminTokenResp.Scope, adminTokenResp.ExpiresIn)

		// Admin should be able to list roles
		rolesResp, err := adminSession.ListRoles(t.Context())

		require.NoError(t, err)
		require.NotEmpty(t, rolesResp.Roles)

		t.Logf("Admin can access admin endpoints successfully")
	})
}

// =========================================
// Helper functions for invite related tests
// =========================================

// setupInviteTest is a helper that bootstraps the service, logs in as admin,
// and finds a role by name. Returns the client, clientID, clientSecret, adminSession, and roleID.
func setupInviteTest(t *testing.T, roleName string) (*authsdk.SDKClient, string, string, *authsdk.Session, string) {
	t.Helper()

	baseURL, cleanup := setupAuthContainer(t)
	t.Cleanup(cleanup)

	client := authsdk.NewSDKClient(baseURL)
	clientID, clientSecret, _ := bootstrapService(t, client)
	adminSession := performLogin(t, client, clientID, clientSecret, adminUsername, adminPassword)
	roleID := findRoleByName(t, adminSession, roleName)

	return client, clientID, clientSecret, adminSession, roleID
}

// createInvite is a helper that mints an invite token for a given role.
// Returns the invite response.
func createInvite(t *testing.T, session *authsdk.Session, clientID, roleID string, reusable bool) *authsdk.InviteResponse {
	t.Helper()

	inviteResp, err := session.MintInvite(t.Context(), authsdk.InviteRequest{
		ClientID: clientID,
		RoleID:   roleID,
		Reusable: reusable,
	})

	require.NoError(t, err)
	require.NotNil(t, inviteResp)
	require.NotEmpty(t, inviteResp.InviteToken)

	return inviteResp
}

// redeemInvite is a helper that redeems an invite token and creates a new user.
// Returns the redeem response.
func redeemInvite(t *testing.T, client *authsdk.SDKClient, inviteToken, username, password, clientID string) *authsdk.RedeemInviteResponse {
	t.Helper()

	redeemResp, err := client.RedeemInvite(t.Context(), authsdk.RedeemInviteRequest{
		InviteToken: inviteToken,
		Username:    username,
		Password:    password,
		ClientID:    clientID,
	})

	require.NoError(t, err)
	require.NotNil(t, redeemResp)
	require.NotEmpty(t, redeemResp.UserID)
	require.Equal(t, username, redeemResp.Username)

	return redeemResp
}
