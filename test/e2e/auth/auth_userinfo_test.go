package auth_test

import (
	"testing"

	"github.com/aussiebroadwan/bartab/pkg/authsdk"
	"github.com/stretchr/testify/require"
)

// TestBootstrapLoginUserInfo tests the complete flow:
// 1. Bootstrap the service
// 2. Login with password grant
// 3. Fetch user info with access token
func TestBootstrapLoginUserInfo(t *testing.T) {
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

	// Fetch UserInfo
	userInfo, err := session.GetUserInfo(t.Context())

	require.NoError(t, err)
	require.NotNil(t, userInfo)
	require.Equal(t, adminUserID, userInfo.UserID, "User ID should match admin user ID")
	require.Equal(t, adminUsername, userInfo.Username, "Username should match")
	require.Equal(t, adminPreferredName, userInfo.PreferredName, "Preferred name should match")
	require.NotEmpty(t, userInfo.Role, "Role should not be empty")

	t.Logf("UserInfo: user_id=%s, username=%s, preferred_name=%s, role=%s",
		userInfo.UserID, userInfo.Username, userInfo.PreferredName, userInfo.Role)
}
