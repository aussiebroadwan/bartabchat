package auth_test

import (
	"testing"

	"github.com/aussiebroadwan/bartab/pkg/authsdk"
	"github.com/stretchr/testify/require"
)

// TestBootstrapLoginRefresh tests the complete flow:
// 1. Bootstrap the service
// 2. Login with password grant
// 3. Refresh the token
// 4. Verify token rotation (new tokens are different from old tokens)
func TestBootstrapLoginRefresh(t *testing.T) {
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
	oldAccessToken := session.AccessToken()
	oldRefreshToken := session.RefreshToken()

	t.Logf("Password grant successful")
	t.Logf("Access Token: %s", oldAccessToken)
	t.Logf("Refresh Token: %s", oldRefreshToken)

	// Refresh token
	tokenResp, err := client.RefreshGrant(t.Context(), clientID, oldRefreshToken)

	require.NoError(t, err)
	assertTokenResponse(t, tokenResp)

	// Verify token rotation
	require.NotEqual(t, oldAccessToken, tokenResp.AccessToken, "Access token should be rotated")
	require.NotEqual(t, oldRefreshToken, tokenResp.RefreshToken, "Refresh token should be rotated")

	t.Logf("Refresh grant successful, tokens rotated")
	t.Logf("New Access Token: %s", tokenResp.AccessToken)
	t.Logf("New Refresh Token: %s", tokenResp.RefreshToken)
}
