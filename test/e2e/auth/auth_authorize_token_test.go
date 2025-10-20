package auth_test

import (
	"errors"
	"testing"

	"github.com/aussiebroadwan/bartab/pkg/authsdk"
	"github.com/stretchr/testify/require"
)

func TestAuthorizeTokenFlowWithPKCE(t *testing.T) {
	baseURL, cleanup := setupAuthContainer(t)
	defer cleanup()

	client := authsdk.NewSDKClient(baseURL)
	clientID, clientSecret, _ := bootstrapService(t, client)

	redirectURI := "https://example.com/callback"
	scopes := []string{"profile:read", "admin:write", "unknown:scope"}

	// Use the SDK's authorization code flow helper
	session, err := client.AuthorizeAndExchange(
		t.Context(),
		clientID,
		clientSecret,
		redirectURI,
		adminUsername,
		adminPassword,
		scopes,
	)
	require.NoError(t, err)
	require.NotNil(t, session)

	// Verify token scopes - unknown:scope should be filtered out
	introspect, err := session.IntrospectToken(t.Context(), session.AccessToken())
	require.NoError(t, err)
	require.True(t, introspect.Active)
	require.Contains(t, introspect.Scope, "profile:read")
	require.Contains(t, introspect.Scope, "admin:write")
	require.NotContains(t, introspect.Scope, "unknown:scope")
	require.Contains(t, introspect.AMR, "pwd")
}

func TestAuthorizeTokenFlowWithMFA(t *testing.T) {
	baseURL, cleanup := setupAuthContainer(t)
	defer cleanup()

	client := authsdk.NewSDKClient(baseURL)
	clientID, clientSecret, _ := bootstrapService(t, client)

	user := createAndEnrollMFAUser(t, client, clientID, clientSecret, "authorize-mfa-user", "AuthorizeMFA123!")

	redirectURI := "https://example.com/callback"
	scopes := []string{"profile:read"}

	// Attempt to authorize - should return MFA required error
	_, err := client.AuthorizeAndExchange(
		t.Context(),
		clientID,
		clientSecret,
		redirectURI,
		user.Username,
		user.Password,
		scopes,
	)
	require.Error(t, err)

	// Check that it's an MFA required error
	var mfaErr *authsdk.MFARequiredError
	require.True(t, errors.As(err, &mfaErr), "expected MFARequiredError")
	require.NotEmpty(t, mfaErr.MFAToken)
	require.Contains(t, mfaErr.Methods, "totp")

	// Generate TOTP code
	totpCode := generateTOTP(t, user.TOTPSecret)

	// Complete MFA challenge
	session, err := client.AuthorizeAndExchangeWithMFA(
		t.Context(),
		clientID,
		clientSecret,
		redirectURI,
		*mfaErr,
		"totp",
		totpCode,
		scopes,
	)
	require.NoError(t, err)
	require.NotNil(t, session)

	// Verify tokens and AMR includes both pwd and mfa
	introspect, err := session.IntrospectToken(t.Context(), session.AccessToken())
	require.NoError(t, err)
	require.True(t, introspect.Active)
	require.Contains(t, introspect.AMR, "pwd")
	require.Contains(t, introspect.AMR, "mfa")
}

func TestAuthorizeTokenFlowWithExistingSession(t *testing.T) {
	baseURL, cleanup := setupAuthContainer(t)
	defer cleanup()

	client := authsdk.NewSDKClient(baseURL)
	clientID, clientSecret, _ := bootstrapService(t, client)

	redirectURI := "https://example.com/callback"

	// Step 1: Perform initial login to get a session with full scopes
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

	t.Logf("Initial session obtained with scopes: %s", initialSession.Scopes())
	t.Logf("Initial access token (first 20 chars): %s...", initialSession.AccessToken()[:20])

	// Verify initial session AMR contains password authentication
	initialIntrospect, err := initialSession.IntrospectToken(t.Context(), initialSession.AccessToken())
	require.NoError(t, err)
	require.Contains(t, initialIntrospect.AMR, "pwd", "Initial session should have password AMR")

	// Step 2: Use the existing session to authorize a new request with a subset of scopes
	// This simulates a user who is already logged in and wants to authorize a new client
	// or request different permissions without re-entering credentials
	// Note: When using session-based authorization, you can request equal or fewer scopes,
	// but not more than what the original session had
	newScopes := []string{"profile:read", "admin:write"}

	pkce, err := authsdk.GeneratePKCEChallenge()
	require.NoError(t, err)

	authCode, err := client.AuthorizeWithBearerToken(
		t.Context(),
		initialSession.AccessToken(),
		clientID,
		redirectURI,
		newScopes,
		pkce,
	)
	require.NoError(t, err)
	require.NotEmpty(t, authCode, "Should receive authorization code")

	t.Logf("Authorization code obtained using existing session: %s", authCode[:20]+"...")

	// Step 3: Exchange the authorization code for new tokens
	tokenResp, err := client.ExchangeAuthorizationCode(
		t.Context(),
		clientID,
		clientSecret,
		authCode,
		redirectURI,
		pkce.Verifier,
	)
	require.NoError(t, err)
	require.NotEmpty(t, tokenResp.AccessToken)
	require.NotEmpty(t, tokenResp.RefreshToken)

	// Step 4: Create a new session with the exchanged tokens
	newSession := client.NewSessionFromTokens(
		clientID,
		tokenResp.AccessToken,
		tokenResp.RefreshToken,
		tokenResp.Scope,
		tokenResp.ExpiresIn,
	)

	t.Logf("New session obtained with scopes: %s", newSession.Scopes())

	// Step 5: Verify the new tokens have the expected properties
	newIntrospect, err := newSession.IntrospectToken(t.Context(), newSession.AccessToken())
	require.NoError(t, err)
	require.True(t, newIntrospect.Active, "New token should be active")

	// Verify scopes - should have the requested scopes
	require.Contains(t, newIntrospect.Scope, "profile:read", "Should have profile:read scope")
	require.Contains(t, newIntrospect.Scope, "admin:write", "Should have admin:write scope")

	// Verify AMR - should preserve the original authentication method (pwd)
	require.Contains(t, newIntrospect.AMR, "pwd", "Should preserve password AMR from original session")

	// Verify the session ID is preserved (session-based auth maintains the same session)
	// This allows tracking all authorizations from a single login session
	require.Equal(t, initialIntrospect.SessionID, newIntrospect.SessionID,
		"Session ID should be preserved when using session-based authorization")

	// Verify the user ID is the same
	require.Equal(t, initialIntrospect.Sub, newIntrospect.Sub,
		"User ID should remain the same")

	// Verify the JTI (token ID) is different for each token
	require.NotEqual(t, initialIntrospect.Jti, newIntrospect.Jti,
		"Each token should have a unique JTI")

	t.Logf("Session-based authorization successful!")
	t.Logf("Original AMR: %v", initialIntrospect.AMR)
	t.Logf("New AMR: %v", newIntrospect.AMR)
	t.Logf("Session ID (preserved): %s", newIntrospect.SessionID)
	t.Logf("Original Token JTI: %s", initialIntrospect.Jti)
	t.Logf("New Token JTI: %s", newIntrospect.Jti)
}
