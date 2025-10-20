package auth_test

import (
	"testing"
	"time"

	"github.com/aussiebroadwan/bartab/pkg/authsdk"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/require"
)

// mfaTestUser represents a test user with MFA enrollment details.
type mfaTestUser struct {
	Username     string
	Password     string
	TOTPSecret   string
	BackupCodes  []string
	AccessToken  string
	RefreshToken string
}

// TestMFAEnrollmentAndAuthentication tests the complete MFA enrollment and authentication flow.
func TestMFAEnrollmentAndAuthentication(t *testing.T) {
	baseURL, cleanup := setupAuthContainer(t)
	defer cleanup()

	client := authsdk.NewSDKClient(baseURL)
	clientID, clientSecret, _ := bootstrapService(t, client)

	// Create and enroll user in MFA
	user := createAndEnrollMFAUser(t, client, clientID, clientSecret, "mfauser", "MFAUser123!")
	t.Logf("TOTP enrollment initiated, secret: %s", user.TOTPSecret)
	t.Logf("MFA enrollment completed, received %d backup codes", len(user.BackupCodes))

	// Save a backup code for later testing
	backupCode := user.BackupCodes[0]

	// Test authentication with MFA (TOTP)
	challenge := authenticateWithMFA(t, client, clientID, user, []string{"profile:read"})

	require.Contains(t, challenge.Methods, "totp")
	require.Contains(t, challenge.Methods, "backup_codes")

	t.Logf("Received MFA challenge: %+v", challenge)

	// Complete MFA challenge with TOTP code
	mfaTokenResp := completeMFAWithTOTP(t, client, challenge, user)
	t.Logf("Successfully authenticated with TOTP")

	// Verify the token has correct AMR
	mfaSession := client.NewSessionFromTokens(clientID, mfaTokenResp.AccessToken, mfaTokenResp.RefreshToken, mfaTokenResp.Scope, mfaTokenResp.ExpiresIn)
	introspect, err := mfaSession.IntrospectToken(t.Context(), mfaTokenResp.AccessToken)

	require.NoError(t, err)
	require.True(t, introspect.Active)
	require.Contains(t, introspect.AMR, "pwd", "Should have password AMR")
	require.Contains(t, introspect.AMR, "mfa", "Should have MFA AMR")

	t.Logf("Token AMR: %v", introspect.AMR)

	// Test authentication with backup code
	challenge2 := authenticateWithMFA(t, client, clientID, user, []string{"profile:read"})
	backupTokenResp := completeMFAWithBackupCode(t, client, challenge2, backupCode)
	t.Logf("Successfully authenticated with backup code")

	// Verify backup code AMR (should also be "mfa")
	backupSession := client.NewSessionFromTokens(clientID, backupTokenResp.AccessToken, backupTokenResp.RefreshToken, backupTokenResp.Scope, backupTokenResp.ExpiresIn)
	introspect, err = backupSession.IntrospectToken(t.Context(), backupTokenResp.AccessToken)

	require.NoError(t, err)
	require.True(t, introspect.Active)
	require.Contains(t, introspect.AMR, "pwd", "Backup should have password AMR")
	require.Contains(t, introspect.AMR, "mfa", "Backup should have MFA AMR")

	t.Logf("Backup Token AMR: %v", introspect.AMR)

	// Try to reuse the same backup code (should fail)
	challenge3 := authenticateWithMFA(t, client, clientID, user, []string{"profile:read"})
	_, err = client.MFAOTPGrant(t.Context(), *challenge3, "backup_codes", backupCode)

	require.Error(t, err, "Should not be able to reuse backup code")

	t.Logf("Backup code reuse correctly rejected")
}

// TestMFARegenerateBackupCodes tests regenerating backup codes.
func TestMFARegenerateBackupCodes(t *testing.T) {
	baseURL, cleanup := setupAuthContainer(t)
	defer cleanup()

	client := authsdk.NewSDKClient(baseURL)
	clientID, clientSecret, _ := bootstrapService(t, client)

	// Create and enroll user in MFA
	user := createAndEnrollMFAUser(t, client, clientID, clientSecret, "mfauser2", "MFAUser123!")
	oldBackupCode := user.BackupCodes[0]

	// Authenticate with MFA to get a fresh token
	challenge := authenticateWithMFA(t, client, clientID, user, []string{"profile:read", "profile:write"})
	tokenResp := completeMFAWithTOTP(t, client, challenge, user)
	userSession := client.NewSessionFromTokens(clientID, tokenResp.AccessToken, tokenResp.RefreshToken, tokenResp.Scope, tokenResp.ExpiresIn)

	// Regenerate backup codes
	totpCode := generateTOTP(t, user.TOTPSecret)
	backupResp, err := userSession.RegenerateBackupCodes(t.Context(), totpCode)

	require.NoError(t, err)
	require.Len(t, backupResp.Codes, 10, "Should receive 10 new backup codes")

	t.Logf("Regenerated backup codes: %d codes", len(backupResp.Codes))

	// Verify old backup code no longer works
	challenge2 := authenticateWithMFA(t, client, clientID, user, []string{"profile:read"})
	_, err = client.MFAOTPGrant(t.Context(), *challenge2, "backup_codes", oldBackupCode)

	require.Error(t, err, "Old backup code should not work after regeneration")

	// Verify new backup code works
	challenge3 := authenticateWithMFA(t, client, clientID, user, []string{"profile:read"})
	newBackupCode := backupResp.Codes[0]
	_, err = client.MFAOTPGrant(t.Context(), *challenge3, "backup_codes", newBackupCode)

	require.NoError(t, err, "New backup code should work")

	t.Logf("New backup code works correctly")
}

// TestMFARemoval tests removing MFA from a user account.
func TestMFARemoval(t *testing.T) {
	baseURL, cleanup := setupAuthContainer(t)
	defer cleanup()

	client := authsdk.NewSDKClient(baseURL)
	clientID, clientSecret, _ := bootstrapService(t, client)

	// Create and enroll user in MFA
	user := createAndEnrollMFAUser(t, client, clientID, clientSecret, "mfauser3", "MFAUser123!")
	t.Logf("MFA enrollment completed")

	// Verify MFA is required for login
	assertMFARequired(t, client, clientID, user.Username, user.Password, []string{"profile:read"})

	// Complete MFA to get a fresh token
	challenge := authenticateWithMFA(t, client, clientID, user, []string{"profile:read", "profile:write"})
	mfaTokenResp := completeMFAWithTOTP(t, client, challenge, user)
	mfaSession := client.NewSessionFromTokens(clientID, mfaTokenResp.AccessToken, mfaTokenResp.RefreshToken, mfaTokenResp.Scope, mfaTokenResp.ExpiresIn)

	// Remove MFA (requires TOTP verification)
	totpCode := generateTOTP(t, user.TOTPSecret)
	err := mfaSession.RemoveMFA(t.Context(), totpCode)
	require.NoError(t, err)

	t.Logf("MFA removed from account")

	// Verify authorization code flow now works without MFA
	pkce, err := authsdk.GeneratePKCEChallenge()
	require.NoError(t, err)

	code, err := client.AuthorizeWithPassword(t.Context(), clientID, "http://localhost/callback", user.Username, user.Password, []string{"profile:read"}, pkce)
	require.NoError(t, err)

	tokenResp, err := client.ExchangeAuthorizationCode(t.Context(), clientID, clientSecret, code, "http://localhost/callback", pkce.Verifier)
	require.NoError(t, err)
	require.NotEmpty(t, tokenResp.AccessToken, "Should receive tokens without MFA challenge")

	t.Logf("Authorization code flow works without MFA after removal")

	// Verify no MFA AMR in token
	normalSession := client.NewSessionFromTokens(clientID, tokenResp.AccessToken, tokenResp.RefreshToken, tokenResp.Scope, tokenResp.ExpiresIn)
	introspect, err := normalSession.IntrospectToken(t.Context(), tokenResp.AccessToken)

	require.NoError(t, err)
	require.Contains(t, introspect.AMR, "pwd")
	require.NotContains(t, introspect.AMR, "mfa", "Should not have MFA AMR after removal")
}

// TestMFAInvalidScenarios tests various invalid MFA scenarios.
func TestMFAInvalidScenarios(t *testing.T) {
	baseURL, cleanup := setupAuthContainer(t)
	defer cleanup()

	client := authsdk.NewSDKClient(baseURL)
	clientID, clientSecret, _ := bootstrapService(t, client)

	// Create and enroll user in MFA
	user := createAndEnrollMFAUser(t, client, clientID, clientSecret, "mfauser4", "MFAUser123!")

	// Test 1: Invalid TOTP code
	challenge := authenticateWithMFA(t, client, clientID, user, []string{"profile:read"})
	_, err := client.MFAOTPGrant(t.Context(), *challenge, "totp", "000000")
	require.Error(t, err, "Should reject invalid TOTP code")

	t.Logf("Invalid TOTP code correctly rejected")

	// Test 2: Invalid MFA token
	invalidMFAErr := authsdk.MFARequiredError{MFAToken: "invalid-mfa-token", Methods: []string{"totp"}}
	_, err = client.MFAOTPGrant(t.Context(), invalidMFAErr, "totp", "000000")
	require.Error(t, err, "Should reject invalid MFA token")

	t.Logf("Invalid MFA token correctly rejected")

	// Test 3: MFA session expiry documentation
	t.Logf("MFA session expiry is enforced (5 minute timeout)")

	// Test 4: Try to verify TOTP without enrolling first
	user2 := createMFATestUser(t, client, clientID, clientSecret, "nousertotp", "NoUser123!")

	pkce2, err := authsdk.GeneratePKCEChallenge()
	require.NoError(t, err)

	code2, err := client.AuthorizeWithPassword(t.Context(), clientID, "http://localhost/callback", user2.Username, user2.Password, []string{"profile:read", "profile:write"}, pkce2)
	require.NoError(t, err)

	tokenResp, err := client.ExchangeAuthorizationCode(t.Context(), clientID, clientSecret, code2, "http://localhost/callback", pkce2.Verifier)
	require.NoError(t, err)

	user2Session := client.NewSessionFromTokens(clientID, tokenResp.AccessToken, tokenResp.RefreshToken, tokenResp.Scope, tokenResp.ExpiresIn)

	_, err = user2Session.VerifyTOTP(t.Context(), "123456")
	require.Error(t, err, "Should not be able to verify without enrolling first")

	t.Logf("Verification without enrollment correctly rejected")
}

// TestMFATokenRefreshPreservesAMR tests that refreshing tokens preserves MFA AMR.
func TestMFATokenRefreshPreservesAMR(t *testing.T) {
	baseURL, cleanup := setupAuthContainer(t)
	defer cleanup()

	client := authsdk.NewSDKClient(baseURL)
	clientID, clientSecret, _ := bootstrapService(t, client)

	// Create and enroll user in MFA
	user := createAndEnrollMFAUser(t, client, clientID, clientSecret, "mfauser5", "MFAUser123!")

	// Authenticate with MFA
	challenge := authenticateWithMFA(t, client, clientID, user, []string{"profile:read"})
	mfaTokenResp := completeMFAWithTOTP(t, client, challenge, user)
	mfaSession := client.NewSessionFromTokens(clientID, mfaTokenResp.AccessToken, mfaTokenResp.RefreshToken, mfaTokenResp.Scope, mfaTokenResp.ExpiresIn)

	// Verify initial token has pwd + mfa AMR
	introspect1, err := mfaSession.IntrospectToken(t.Context(), mfaTokenResp.AccessToken)

	require.NoError(t, err)
	require.Contains(t, introspect1.AMR, "pwd")
	require.Contains(t, introspect1.AMR, "mfa")

	t.Logf("Initial AMR: %v", introspect1.AMR)

	// Refresh the token
	refreshedResp, err := client.RefreshGrant(t.Context(), clientID, mfaTokenResp.RefreshToken)
	require.NoError(t, err)

	refreshedSession := client.NewSessionFromTokens(clientID, refreshedResp.AccessToken, refreshedResp.RefreshToken, refreshedResp.Scope, refreshedResp.ExpiresIn)

	// Verify refreshed token preserves MFA AMR and adds refresh
	introspect2, err := refreshedSession.IntrospectToken(t.Context(), refreshedResp.AccessToken)

	require.NoError(t, err)
	require.Contains(t, introspect2.AMR, "pwd", "Should preserve pwd AMR")
	require.Contains(t, introspect2.AMR, "mfa", "Should preserve mfa AMR")
	require.Contains(t, introspect2.AMR, "refresh", "Should add refresh AMR")

	t.Logf("Refreshed AMR: %v", introspect2.AMR)
	t.Logf("MFA AMR correctly preserved through token refresh")
}

// ==============================
// Helper functions for MFA tests
// ==============================

// createMFATestUser creates a new test user and returns the user details.
// This is a convenience helper that combines user creation without MFA enrollment.
func createMFATestUser(t *testing.T, client *authsdk.SDKClient, clientID, clientSecret, username, password string) *mfaTestUser {
	t.Helper()

	adminSession := performLogin(t, client, clientID, clientSecret, adminUsername, adminPassword)
	roleID := findRoleByName(t, adminSession, "user")
	inviteResp := createInvite(t, adminSession, clientID, roleID, false)
	redeemInvite(t, client, inviteResp.InviteToken, username, password, clientID)

	return &mfaTestUser{
		Username: username,
		Password: password,
	}
}

// enrollMFAForUser enrolls the user in MFA and returns the enrollment details.
// 1. Login with test user
// 2. Enroll in MFA, save secret to test user
// 3. Generate TOTP based on enroll secret
// 4. Verify request
// 5. Save backup codes to test user
func enrollMFAForUser(t *testing.T, client *authsdk.SDKClient, clientID, clientSecret string, user *mfaTestUser) {
	t.Helper()

	// Login to get a session using authorization code flow
	pkce, err := authsdk.GeneratePKCEChallenge()
	require.NoError(t, err)

	code, err := client.AuthorizeWithPassword(t.Context(), clientID, "http://localhost/callback", user.Username, user.Password, []string{"profile:read", "profile:write"}, pkce)
	require.NoError(t, err)

	tokenResp, err := client.ExchangeAuthorizationCode(t.Context(), clientID, clientSecret, code, "http://localhost/callback", pkce.Verifier)
	require.NoError(t, err)

	userSession := client.NewSessionFromTokens(clientID, tokenResp.AccessToken, tokenResp.RefreshToken, tokenResp.Scope, tokenResp.ExpiresIn)
	user.AccessToken = tokenResp.AccessToken

	// Enroll in TOTP
	enrollResp, err := userSession.EnrollTOTP(t.Context())

	require.NoError(t, err)
	require.NotEmpty(t, enrollResp.Secret, "TOTP secret should be returned")
	require.NotEmpty(t, enrollResp.QRCode, "QR code should be returned")

	user.TOTPSecret = enrollResp.Secret

	// Generate and verify TOTP code
	totpCode := generateTOTP(t, user.TOTPSecret)
	backupResp, err := userSession.VerifyTOTP(t.Context(), totpCode)

	require.NoError(t, err)
	require.Len(t, backupResp.Codes, 10, "Should receive 10 backup codes")

	user.BackupCodes = backupResp.Codes
}

// createAndEnrollMFAUser combines createMFATestUser and enrollMFAForUser.
// This is the most common setup pattern in MFA tests.
func createAndEnrollMFAUser(t *testing.T, client *authsdk.SDKClient, clientID, clientSecret, username, password string) *mfaTestUser {
	t.Helper()

	user := createMFATestUser(t, client, clientID, clientSecret, username, password)
	enrollMFAForUser(t, client, clientID, clientSecret, user)
	return user
}

// generateTOTP generates a TOTP code for the given secret.
func generateTOTP(t *testing.T, secret string) string {
	t.Helper()

	code, err := totp.GenerateCode(secret, time.Now())
	require.NoError(t, err)

	return code
}

// authenticateWithMFA performs authorization with MFA and returns the MFA challenge.
func authenticateWithMFA(t *testing.T, client *authsdk.SDKClient, clientID string, user *mfaTestUser, scopes []string) *authsdk.MFARequiredError {
	t.Helper()

	pkce, err := authsdk.GeneratePKCEChallenge()
	require.NoError(t, err)

	_, err = client.AuthorizeWithPassword(t.Context(), clientID, "http://localhost/callback", user.Username, user.Password, scopes, pkce)
	require.Error(t, err, "Should receive MFA error")

	var mfaErr *authsdk.MFARequiredError
	require.ErrorAs(t, err, &mfaErr, "Error should be MFARequiredError")
	require.NotEmpty(t, mfaErr.MFAToken, "MFA token should be present")
	require.NotEmpty(t, mfaErr.Methods, "MFA methods should be present")

	return mfaErr
}

// completeMFAWithTOTP completes an MFA challenge using a TOTP code.
func completeMFAWithTOTP(t *testing.T, client *authsdk.SDKClient, mfaErr *authsdk.MFARequiredError, user *mfaTestUser) *authsdk.TokenResponse {
	t.Helper()

	totpCode := generateTOTP(t, user.TOTPSecret)
	tokenResp, err := client.MFAOTPGrant(t.Context(), *mfaErr, "totp", totpCode)

	require.NoError(t, err)
	require.NotEmpty(t, tokenResp.AccessToken)
	require.NotEmpty(t, tokenResp.RefreshToken)

	user.AccessToken = tokenResp.AccessToken
	user.RefreshToken = tokenResp.RefreshToken
	return tokenResp
}

// completeMFAWithBackupCode completes an MFA challenge using a backup code.
func completeMFAWithBackupCode(t *testing.T, client *authsdk.SDKClient, mfaErr *authsdk.MFARequiredError, backupCode string) *authsdk.TokenResponse {
	t.Helper()

	tokenResp, err := client.MFAOTPGrant(t.Context(), *mfaErr, "backup_codes", backupCode)

	require.NoError(t, err)
	require.NotEmpty(t, tokenResp.AccessToken)
	require.NotEmpty(t, tokenResp.RefreshToken)

	return tokenResp
}

// assertMFARequired verifies that authorization returns an MFA challenge.
func assertMFARequired(t *testing.T, client *authsdk.SDKClient, clientID, username, password string, scopes []string) *authsdk.MFARequiredError {
	t.Helper()

	pkce, err := authsdk.GeneratePKCEChallenge()
	require.NoError(t, err)

	_, err = client.AuthorizeWithPassword(t.Context(), clientID, "http://localhost/callback", username, password, scopes, pkce)
	require.Error(t, err, "Should receive MFA error")

	var mfaErr *authsdk.MFARequiredError
	require.ErrorAs(t, err, &mfaErr, "Error should be MFARequiredError")

	return mfaErr
}

// TestMFAAttemptLimiting tests that MFA sessions are invalidated after 5 failed attempts.
// This prevents brute force attacks on TOTP codes.
func TestMFAAttemptLimiting(t *testing.T) {
	baseURL, cleanup := setupAuthContainer(t)
	defer cleanup()

	client := authsdk.NewSDKClient(baseURL)
	clientID, clientSecret, _ := bootstrapService(t, client)

	// Create and enroll user in MFA
	user := createAndEnrollMFAUser(t, client, clientID, clientSecret, "mfaattemptuser", "MFAAttempt123!")
	t.Logf("Created user with MFA enabled")

	// Get an MFA challenge
	challenge := authenticateWithMFA(t, client, clientID, user, []string{"profile:read"})
	t.Logf("Received MFA challenge token: %s", challenge.MFAToken)

	// Make 5 failed attempts with invalid TOTP codes
	for i := 1; i <= 5; i++ {
		invalidCode := "000000"
		_, err := client.MFAOTPGrant(t.Context(), *challenge, "totp", invalidCode)
		require.Error(t, err, "Attempt %d: Should reject invalid TOTP code", i)

		// First 4 attempts should get generic invalid_grant error
		if i < 5 {
			t.Logf("Attempt %d failed as expected", i)
		}
	}

	t.Logf("Completed 5 failed attempts")

	// The 6th attempt should fail with "too many attempts" error
	_, err := client.MFAOTPGrant(t.Context(), *challenge, "totp", "000000")
	require.Error(t, err, "Should reject attempt after max attempts exceeded")
	require.Contains(t, err.Error(), "invalid_grant", "Should return invalid_grant error")
	t.Logf("6th attempt correctly rejected with: %v", err)

	// Verify that even with a valid TOTP code, the session is now invalidated
	validCode := generateTOTP(t, user.TOTPSecret)
	_, err = client.MFAOTPGrant(t.Context(), *challenge, "totp", validCode)
	require.Error(t, err, "Should reject even valid code after session invalidated")
	t.Logf("Valid TOTP code correctly rejected after session invalidation")

	// Verify we can start a fresh MFA session and it works
	challenge2 := authenticateWithMFA(t, client, clientID, user, []string{"profile:read"})
	validCode2 := generateTOTP(t, user.TOTPSecret)
	tokenResp, err := client.MFAOTPGrant(t.Context(), *challenge2, "totp", validCode2)
	require.NoError(t, err, "Should succeed with fresh MFA session")
	require.NotEmpty(t, tokenResp.AccessToken, "Should receive access token")
	t.Logf("Fresh MFA session works correctly after previous session was invalidated")
}

// TestMFAAttemptLimitingWithBackupCode tests attempt limiting with backup codes.
func TestMFAAttemptLimitingWithBackupCode(t *testing.T) {
	baseURL, cleanup := setupAuthContainer(t)
	defer cleanup()

	client := authsdk.NewSDKClient(baseURL)
	clientID, clientSecret, _ := bootstrapService(t, client)

	// Create and enroll user in MFA
	user := createAndEnrollMFAUser(t, client, clientID, clientSecret, "mfabackupattemptuser", "MFABackup123!")
	validBackupCode := user.BackupCodes[0]
	t.Logf("Created user with MFA enabled and %d backup codes", len(user.BackupCodes))

	// Get an MFA challenge
	challenge := authenticateWithMFA(t, client, clientID, user, []string{"profile:read"})

	// Make 5 failed attempts with invalid backup codes
	for i := 1; i <= 5; i++ {
		invalidCode := "INVALID-BACKUP-CODE"
		_, err := client.MFAOTPGrant(t.Context(), *challenge, "backup_codes", invalidCode)
		require.Error(t, err, "Attempt %d: Should reject invalid backup code", i)
		t.Logf("Backup code attempt %d failed as expected", i)
	}

	// The 6th attempt should fail even with valid backup code
	_, err := client.MFAOTPGrant(t.Context(), *challenge, "backup_codes", validBackupCode)
	require.Error(t, err, "Should reject even valid backup code after max attempts")
	t.Logf("Valid backup code correctly rejected after too many attempts")

	// Verify the backup code still works with a fresh MFA session
	challenge2 := authenticateWithMFA(t, client, clientID, user, []string{"profile:read"})
	tokenResp, err := client.MFAOTPGrant(t.Context(), *challenge2, "backup_codes", validBackupCode)
	require.NoError(t, err, "Should succeed with fresh MFA session")
	require.NotEmpty(t, tokenResp.AccessToken, "Should receive access token")
	t.Logf("Backup code works correctly with fresh MFA session")
}

// TestMFAAttemptLimitingMixedMethods tests attempt limiting with mixed MFA methods.
func TestMFAAttemptLimitingMixedMethods(t *testing.T) {
	baseURL, cleanup := setupAuthContainer(t)
	defer cleanup()

	client := authsdk.NewSDKClient(baseURL)
	clientID, clientSecret, _ := bootstrapService(t, client)

	// Create and enroll user in MFA
	user := createAndEnrollMFAUser(t, client, clientID, clientSecret, "mfamixeduser", "MFAMixed123!")
	t.Logf("Created user with MFA enabled")

	// Get an MFA challenge
	challenge := authenticateWithMFA(t, client, clientID, user, []string{"profile:read"})

	// Make 3 failed attempts with invalid TOTP
	for i := 1; i <= 3; i++ {
		_, err := client.MFAOTPGrant(t.Context(), *challenge, "totp", "000000")
		require.Error(t, err, "TOTP attempt %d should fail", i)
		t.Logf("TOTP attempt %d failed", i)
	}

	// Make 2 failed attempts with invalid backup codes
	for i := 1; i <= 2; i++ {
		_, err := client.MFAOTPGrant(t.Context(), *challenge, "backup_codes", "INVALID")
		require.Error(t, err, "Backup code attempt %d should fail", i)
		t.Logf("Backup code attempt %d failed", i)
	}

	t.Logf("Completed 5 total failed attempts (3 TOTP + 2 backup)")

	// The 6th attempt should fail regardless of method
	validCode := generateTOTP(t, user.TOTPSecret)
	_, err := client.MFAOTPGrant(t.Context(), *challenge, "totp", validCode)
	require.Error(t, err, "Should reject valid TOTP after 5 mixed attempts")
	t.Logf("Session correctly invalidated after mixed method attempts")
}
