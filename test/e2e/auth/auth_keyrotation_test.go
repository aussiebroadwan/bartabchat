package auth_test

import (
	"testing"
	"time"

	"github.com/aussiebroadwan/bartab/pkg/authsdk"
	"github.com/stretchr/testify/require"
)

// TestKeyRotation verifies the key rotation flow:
// 1. Bootstrap the service
// 2. Login as admin
// 3. List initial keys (should have 1 key)
// 4. Rotate keys without retiring existing
// 5. List keys (should have 2 keys)
// 6. Rotate keys with retire_existing=true
// 7. List keys (should have 1 active key + 1 retired key)
func TestKeyRotation(t *testing.T) {
	baseURL, cleanup := setupAuthContainer(t)
	defer cleanup()

	client := authsdk.NewSDKClient(baseURL)

	// 1. Bootstrap the service
	clientID, clientSecret, _ := bootstrapService(t, client)
	t.Logf("Bootstrap successful, client ID: %s", clientID)

	// 2. Login with admin user
	session := performLogin(t, client, clientID, clientSecret, adminUsername, adminPassword)
	t.Logf("Login successful")

	// 3. List initial keys - should have exactly 1 key
	initialKeys, err := session.ListKeys(t.Context())
	require.NoError(t, err, "Should list keys successfully")
	require.Len(t, initialKeys, 1, "Should have exactly 1 initial key")

	initialKey := initialKeys[0]
	require.NotEmpty(t, initialKey.Kid, "Key ID should not be empty")
	require.NotEmpty(t, initialKey.Algorithm, "Algorithm should not be empty")
	require.Nil(t, initialKey.RetiredAt, "Initial key should not be retired")

	t.Logf("Initial key: kid=%s, algorithm=%s", initialKey.Kid, initialKey.Algorithm)

	// 4. Rotate keys without retiring existing (add a second key)
	rotateResp1, err := session.RotateKey(t.Context(), authsdk.RotateKeyRequest{
		RetireExisting: false,
	})
	require.NoError(t, err, "Should rotate keys successfully")
	require.NotNil(t, rotateResp1)
	require.NotEmpty(t, rotateResp1.NewKey.Kid, "New key should have a kid")
	require.Empty(t, rotateResp1.RetiredKeys, "Should not retire any keys")
	require.Equal(t, 2, rotateResp1.ActiveKeys, "Should have 2 active keys")

	t.Logf("Rotated without retiring: new_kid=%s, active_keys=%d", rotateResp1.NewKey.Kid, rotateResp1.ActiveKeys)

	// 5. List keys - should now have 2 keys
	keysAfterFirstRotation, err := session.ListKeys(t.Context())
	require.NoError(t, err, "Should list keys successfully")
	require.Len(t, keysAfterFirstRotation, 2, "Should have 2 keys after rotation")

	// Verify both keys are active
	for _, key := range keysAfterFirstRotation {
		require.Nil(t, key.RetiredAt, "All keys should be active")
	}

	t.Logf("Keys after first rotation: %d keys", len(keysAfterFirstRotation))

	// 6. Manually retire the first key to verify retirement works
	err = session.RetireKey(t.Context(), initialKeys[0].Kid)
	require.NoError(t, err, "Should retire first key successfully")

	t.Logf("Retired first key: kid=%s", initialKeys[0].Kid)

	// 7. List keys - in ephemeral mode, retired keys are not returned by ListKeys
	// Note: Retired keys remain in KeySet for token verification, but not in the signer list
	keysAfterRetirement, err := session.ListKeys(t.Context())
	require.NoError(t, err, "Should list keys successfully")
	// After retiring one key, we should have 1 active key remaining
	require.Len(t, keysAfterRetirement, 1, "Should have 1 active key (ephemeral mode doesn't return retired keys)")

	// Verify the remaining key is active
	require.Nil(t, keysAfterRetirement[0].RetiredAt, "Remaining key should be active")
	require.NotEqual(t, initialKeys[0].Kid, keysAfterRetirement[0].Kid, "Remaining key should not be the retired one")

	t.Logf("Keys after retirement: %d active keys (retired keys not shown in ephemeral mode)", len(keysAfterRetirement))
}

// TestRetireKey verifies the retire key flow:
// 1. Bootstrap and login
// 2. Add a second key (without retiring)
// 3. Retire the first key by its kid
// 4. Verify the key was retired
func TestRetireKey(t *testing.T) {
	baseURL, cleanup := setupAuthContainer(t)
	defer cleanup()

	client := authsdk.NewSDKClient(baseURL)

	// 1. Bootstrap and login
	clientID, clientSecret, _ := bootstrapService(t, client)
	session := performLogin(t, client, clientID, clientSecret, adminUsername, adminPassword)

	t.Logf("Bootstrap and login successful")

	// 2. Get initial key
	initialKeys, err := session.ListKeys(t.Context())
	require.NoError(t, err)
	require.Len(t, initialKeys, 1)
	initialKeyKid := initialKeys[0].Kid

	t.Logf("Initial key: kid=%s", initialKeyKid)

	// 3. Add a second key without retiring
	rotateResp, err := session.RotateKey(t.Context(), authsdk.RotateKeyRequest{
		RetireExisting: false,
	})
	require.NoError(t, err)
	require.Equal(t, 2, rotateResp.ActiveKeys)

	t.Logf("Added second key: kid=%s", rotateResp.NewKey.Kid)

	// 4. Retire the initial key
	err = session.RetireKey(t.Context(), initialKeyKid)
	require.NoError(t, err, "Should retire key successfully")

	t.Logf("Retired key: kid=%s", initialKeyKid)

	// 5. List keys and verify retirement
	// Note: In ephemeral mode, retired keys are not returned by ListKeys
	keys, err := session.ListKeys(t.Context())
	require.NoError(t, err)
	require.Len(t, keys, 1, "Should have 1 active key (ephemeral mode doesn't return retired keys)")

	// Verify the remaining key is active and is not the retired one
	activeKey := keys[0]
	require.Nil(t, activeKey.RetiredAt, "Active key should not have RetiredAt timestamp")
	require.NotEqual(t, initialKeyKid, activeKey.Kid, "Active key should not be the retired one")

	t.Logf("Verified: retired_key=%s is no longer in active list, active_key=%s is still active",
		initialKeyKid, activeKey.Kid)
}

// TestKeyRotationTokenVerification verifies that tokens issued before rotation
// can still be verified after rotation (backward compatibility).
// 1. Bootstrap and login (get a token)
// 2. Verify the token works
// 3. Rotate keys without retiring
// 4. Verify the old token still works
// 5. Get a new token with the new key
// 6. Verify the new token works
func TestKeyRotationTokenVerification(t *testing.T) {
	baseURL, cleanup := setupAuthContainer(t)
	defer cleanup()

	client := authsdk.NewSDKClient(baseURL)

	// 1. Bootstrap and login
	clientID, clientSecret, _ := bootstrapService(t, client)
	session := performLogin(t, client, clientID, clientSecret, adminUsername, adminPassword)
	oldAccessToken := session.AccessToken()

	t.Logf("Got initial access token")

	// 2. Verify the old token works
	userInfo, err := session.GetUserInfo(t.Context())
	require.NoError(t, err, "Should get user info with old token")
	require.Equal(t, adminUsername, userInfo.Username)

	t.Logf("Old token verified: username=%s", userInfo.Username)

	// 3. Rotate keys without retiring (add new key)
	rotateResp, err := session.RotateKey(t.Context(), authsdk.RotateKeyRequest{
		RetireExisting: false,
	})
	require.NoError(t, err)
	require.Equal(t, 2, rotateResp.ActiveKeys, "Should have 2 active keys")

	t.Logf("Rotated keys: new_kid=%s, active_keys=%d", rotateResp.NewKey.Kid, rotateResp.ActiveKeys)

	// 4. Verify the old token still works (backward compatibility)
	userInfo2, err := session.GetUserInfo(t.Context())
	require.NoError(t, err, "Should still get user info with old token after rotation")
	require.Equal(t, adminUsername, userInfo2.Username)

	t.Logf("Old token still works after rotation")

	// 5. Refresh to get a new token (should use the new key)
	newSession, err := client.AuthenticateWithRefreshToken(t.Context(), clientID, session.RefreshToken())
	require.NoError(t, err, "Should refresh token successfully")
	newAccessToken := newSession.AccessToken()

	// Verify the new token is different
	require.NotEqual(t, oldAccessToken, newAccessToken, "New token should be different")

	t.Logf("Got new access token via refresh")

	// 6. Verify the new token works
	userInfo3, err := newSession.GetUserInfo(t.Context())
	require.NoError(t, err, "Should get user info with new token")
	require.Equal(t, adminUsername, userInfo3.Username)

	t.Logf("New token verified: username=%s", userInfo3.Username)
}

// TestKeyRotationWithRetireGracePeriod verifies that when keys are
// retired, tokens signed with retired keys remain valid during the grace period.
func TestKeyRotationWithRetireGracePeriod(t *testing.T) {
	baseURL, cleanup := setupAuthContainer(t)
	defer cleanup()

	client := authsdk.NewSDKClient(baseURL)

	// 1. Bootstrap and login (get a token with the initial key)
	clientID, clientSecret, _ := bootstrapService(t, client)
	session := performLogin(t, client, clientID, clientSecret, adminUsername, adminPassword)

	t.Logf("Got initial access token")

	// 2. Verify the token works
	userInfo, err := session.GetUserInfo(t.Context())
	require.NoError(t, err, "Should get user info with initial token")
	require.Equal(t, adminUsername, userInfo.Username)

	t.Logf("Initial token verified")

	// 3. Get the initial key ID
	keys, err := session.ListKeys(t.Context())
	require.NoError(t, err)
	require.Len(t, keys, 1)
	initialKeyKid := keys[0].Kid

	t.Logf("Initial key: kid=%s", initialKeyKid)

	// 4. Add a second key (so we can retire the first one)
	addResp, err := session.RotateKey(t.Context(), authsdk.RotateKeyRequest{
		RetireExisting: false,
	})
	require.NoError(t, err)
	require.Equal(t, 2, addResp.ActiveKeys, "Should have 2 active keys")

	t.Logf("Added second key: kid=%s", addResp.NewKey.Kid)

	// 5. Retire the first key
	err = session.RetireKey(t.Context(), initialKeyKid)
	require.NoError(t, err, "Should retire first key successfully")

	t.Logf("Retired first key: kid=%s", initialKeyKid)

	// 6. Verify the old token STILL WORKS during grace period
	// The retired key should still be available for verification
	userInfo2, err := session.GetUserInfo(t.Context())
	require.NoError(t, err, "Should still verify token with retired key during grace period")
	require.Equal(t, adminUsername, userInfo2.Username)

	t.Logf("Token signed with retired key still works during grace period")

	// 7. Get a new token (should use the new key)
	newSession, err := client.AuthenticateWithRefreshToken(t.Context(), clientID, session.RefreshToken())
	require.NoError(t, err, "Should refresh token successfully")

	t.Logf("Got new token with new key")

	// 8. Verify the new token works
	userInfo3, err := newSession.GetUserInfo(t.Context())
	require.NoError(t, err, "Should get user info with new token")
	require.Equal(t, adminUsername, userInfo3.Username)

	t.Logf("New token verified successfully")
}

// TestRetireKeyNotFound verifies that retiring a non-existent key returns an error.
func TestRetireKeyNotFound(t *testing.T) {
	baseURL, cleanup := setupAuthContainer(t)
	defer cleanup()

	client := authsdk.NewSDKClient(baseURL)

	// Bootstrap and login
	clientID, clientSecret, _ := bootstrapService(t, client)
	session := performLogin(t, client, clientID, clientSecret, adminUsername, adminPassword)

	// Try to retire a non-existent key
	err := session.RetireKey(t.Context(), "nonexistent-key-id")
	require.Error(t, err, "Should fail to retire non-existent key")

	t.Logf("Correctly rejected non-existent key: %v", err)
}

// TestRetireLastKeyRejected verifies that the service prevents retiring the last signing key.
func TestRetireLastKeyRejected(t *testing.T) {
	baseURL, cleanup := setupAuthContainer(t)
	defer cleanup()

	client := authsdk.NewSDKClient(baseURL)

	// Bootstrap and login
	clientID, clientSecret, _ := bootstrapService(t, client)
	session := performLogin(t, client, clientID, clientSecret, adminUsername, adminPassword)

	// Get the only key
	keys, err := session.ListKeys(t.Context())
	require.NoError(t, err)
	require.Len(t, keys, 1, "Should have exactly 1 key")
	onlyKeyKid := keys[0].Kid

	t.Logf("Only key: kid=%s", onlyKeyKid)

	// Try to retire the only key (should fail)
	err = session.RetireKey(t.Context(), onlyKeyKid)
	require.Error(t, err, "Should not be able to retire the last signing key")
	require.Contains(t, err.Error(), "cannot retire the last signing key", "Error should mention the business rule")

	t.Logf("Correctly prevented retirement of last key: %v", err)

	// Verify the key is still active
	keys, err = session.ListKeys(t.Context())
	require.NoError(t, err)
	require.Len(t, keys, 1)
	require.Nil(t, keys[0].RetiredAt, "Key should still be active")

	t.Logf("Key remains active after rejected retirement")
}

// TestRetireKeyUnauthorized verifies that non-admin users cannot retire keys.
func TestRetireKeyUnauthorized(t *testing.T) {
	baseURL, cleanup := setupAuthContainer(t)
	defer cleanup()

	client := authsdk.NewSDKClient(baseURL)

	// 1. Bootstrap the service
	clientID, clientSecret, _ := bootstrapService(t, client)

	// 2. Create a regular user with user role
	adminSession := performLogin(t, client, clientID, clientSecret, adminUsername, adminPassword)

	// Find the "user" role
	userRoleID := findRoleByName(t, adminSession, "user")

	// Mint an invite for the user role
	invite, err := adminSession.MintInvite(t.Context(), authsdk.InviteRequest{
		ClientID: clientID,
		RoleID:   userRoleID,
	})
	require.NoError(t, err)

	// Redeem the invite to create a regular user
	regularUsername := "regularuser"
	regularPassword := "Regular123!"
	_, err = client.RedeemInvite(t.Context(), authsdk.RedeemInviteRequest{
		InviteToken: invite.InviteToken,
		Username:    regularUsername,
		Password:    regularPassword,
		ClientID:    clientID,
	})
	require.NoError(t, err)

	// 3. Login as regular user
	regularSession := performLogin(t, client, clientID, clientSecret, regularUsername, regularPassword)

	// 4. Get a key to retire
	keys, err := adminSession.ListKeys(t.Context())
	require.NoError(t, err)
	require.NotEmpty(t, keys)
	keyToRetire := keys[0].Kid

	// 5. Try to retire the key as regular user (should fail)
	err = regularSession.RetireKey(t.Context(), keyToRetire)
	assertCannotAccessEndpoint(t, err, "Regular user should not be able to retire keys")

	t.Logf("Correctly rejected unauthorized key retirement attempt")
}

// TestListKeysUnauthorized verifies that non-admin users cannot list keys.
func TestListKeysUnauthorized(t *testing.T) {
	baseURL, cleanup := setupAuthContainer(t)
	defer cleanup()

	client := authsdk.NewSDKClient(baseURL)

	// 1. Bootstrap the service
	clientID, clientSecret, _ := bootstrapService(t, client)

	// 2. Create a regular user
	adminSession := performLogin(t, client, clientID, clientSecret, adminUsername, adminPassword)
	userRoleID := findRoleByName(t, adminSession, "user")

	invite, err := adminSession.MintInvite(t.Context(), authsdk.InviteRequest{
		ClientID: clientID,
		RoleID:   userRoleID,
	})
	require.NoError(t, err)

	regularUsername := "regularuser"
	regularPassword := "Regular123!"
	_, err = client.RedeemInvite(t.Context(), authsdk.RedeemInviteRequest{
		InviteToken: invite.InviteToken,
		Username:    regularUsername,
		Password:    regularPassword,
		ClientID:    clientID,
	})
	require.NoError(t, err)

	// 3. Login as regular user
	regularSession := performLogin(t, client, clientID, clientSecret, regularUsername, regularPassword)

	// 4. Try to list keys (should fail)
	_, err = regularSession.ListKeys(t.Context())
	assertCannotAccessEndpoint(t, err, "Regular user should not be able to list keys")

	t.Logf("Correctly rejected unauthorized key listing attempt")
}

// TestRotateKeyUnauthorized verifies that non-admin users cannot rotate keys.
func TestRotateKeyUnauthorized(t *testing.T) {
	baseURL, cleanup := setupAuthContainer(t)
	defer cleanup()

	client := authsdk.NewSDKClient(baseURL)

	// 1. Bootstrap the service
	clientID, clientSecret, _ := bootstrapService(t, client)

	// 2. Create a regular user
	adminSession := performLogin(t, client, clientID, clientSecret, adminUsername, adminPassword)
	userRoleID := findRoleByName(t, adminSession, "user")

	invite, err := adminSession.MintInvite(t.Context(), authsdk.InviteRequest{
		ClientID: clientID,
		RoleID:   userRoleID,
	})
	require.NoError(t, err)

	regularUsername := "regularuser"
	regularPassword := "Regular123!"
	_, err = client.RedeemInvite(t.Context(), authsdk.RedeemInviteRequest{
		InviteToken: invite.InviteToken,
		Username:    regularUsername,
		Password:    regularPassword,
		ClientID:    clientID,
	})
	require.NoError(t, err)

	// 3. Login as regular user
	regularSession := performLogin(t, client, clientID, clientSecret, regularUsername, regularPassword)

	// 4. Try to rotate keys (should fail)
	_, err = regularSession.RotateKey(t.Context(), authsdk.RotateKeyRequest{
		RetireExisting: false,
	})
	assertCannotAccessEndpoint(t, err, "Regular user should not be able to rotate keys")

	t.Logf("Correctly rejected unauthorized key rotation attempt")
}

// TestMultipleRotationsTracking verifies that multiple key rotations are tracked correctly.
func TestMultipleRotationsTracking(t *testing.T) {
	baseURL, cleanup := setupAuthContainer(t)
	defer cleanup()

	client := authsdk.NewSDKClient(baseURL)

	// Bootstrap and login
	clientID, clientSecret, _ := bootstrapService(t, client)
	session := performLogin(t, client, clientID, clientSecret, adminUsername, adminPassword)

	// Track all key IDs we see
	seenKids := make(map[string]bool)

	// Get initial key
	keys, err := session.ListKeys(t.Context())
	require.NoError(t, err)
	require.Len(t, keys, 1)
	seenKids[keys[0].Kid] = true

	t.Logf("Initial key: %s", keys[0].Kid)

	// Perform 3 rotations
	for i := 1; i <= 3; i++ {
		// Wait a small amount to ensure different timestamps
		time.Sleep(10 * time.Millisecond)

		resp, err := session.RotateKey(t.Context(), authsdk.RotateKeyRequest{
			RetireExisting: false,
		})
		require.NoError(t, err)
		require.Equal(t, i+1, resp.ActiveKeys, "Should have correct number of active keys")

		// Verify we got a new unique key
		require.False(t, seenKids[resp.NewKey.Kid], "New key should be unique")
		seenKids[resp.NewKey.Kid] = true

		t.Logf("Rotation %d: new_kid=%s, active_keys=%d", i, resp.NewKey.Kid, resp.ActiveKeys)
	}

	// List all keys - should have 4 total
	finalKeys, err := session.ListKeys(t.Context())
	require.NoError(t, err)
	require.Len(t, finalKeys, 4, "Should have 4 keys total")

	// All should be active
	for _, key := range finalKeys {
		require.Nil(t, key.RetiredAt, "All keys should be active")
	}

	t.Logf("Final state: %d keys, all active", len(finalKeys))
}
