package authsdk

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGeneratePKCEChallenge(t *testing.T) {
	t.Parallel()

	pkce, err := GeneratePKCEChallenge()
	require.NoError(t, err)
	require.NotNil(t, pkce)

	// Verify verifier is not empty
	require.NotEmpty(t, pkce.Verifier)

	// Verify challenge is base64url encoded
	require.NotEmpty(t, pkce.Challenge)

	// Verify method is S256
	require.Equal(t, "S256", pkce.Method)

	// Verify challenge is correctly computed from verifier
	hash := sha256.Sum256([]byte(pkce.Verifier))
	expectedChallenge := base64.RawURLEncoding.EncodeToString(hash[:])
	require.Equal(t, expectedChallenge, pkce.Challenge)
}

func TestBuildAuthorizeURL(t *testing.T) {
	t.Parallel()

	client := NewSDKClient("https://auth.example.com")

	t.Run("minimal parameters", func(t *testing.T) {
		url := client.BuildAuthorizeURL("test-client", "https://app.example.com/callback", "", nil, nil)
		require.Contains(t, url, "https://auth.example.com/v1/oauth2/authorize")
		require.Contains(t, url, "response_type=code")
		require.Contains(t, url, "client_id=test-client")
		require.Contains(t, url, "redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback")
	})

	t.Run("with state", func(t *testing.T) {
		url := client.BuildAuthorizeURL("test-client", "https://app.example.com/callback", "random-state", nil, nil)
		require.Contains(t, url, "state=random-state")
	})

	t.Run("with scopes", func(t *testing.T) {
		scopes := []string{"profile:read", "admin:write"}
		url := client.BuildAuthorizeURL("test-client", "https://app.example.com/callback", "", scopes, nil)
		require.Contains(t, url, "scope=profile%3Aread+admin%3Awrite")
	})

	t.Run("with PKCE", func(t *testing.T) {
		pkce, err := GeneratePKCEChallenge()
		require.NoError(t, err)

		url := client.BuildAuthorizeURL("test-client", "https://app.example.com/callback", "", nil, pkce)
		require.Contains(t, url, "code_challenge="+pkce.Challenge)
		require.Contains(t, url, "code_challenge_method=S256")
	})

	t.Run("all parameters", func(t *testing.T) {
		pkce, err := GeneratePKCEChallenge()
		require.NoError(t, err)

		scopes := []string{"profile:read"}
		url := client.BuildAuthorizeURL("test-client", "https://app.example.com/callback", "state123", scopes, pkce)

		require.Contains(t, url, "response_type=code")
		require.Contains(t, url, "client_id=test-client")
		require.Contains(t, url, "redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback")
		require.Contains(t, url, "state=state123")
		require.Contains(t, url, "scope=profile%3Aread")
		require.Contains(t, url, "code_challenge="+pkce.Challenge)
		require.Contains(t, url, "code_challenge_method=S256")
	})
}

func TestParseAuthorizationCallback(t *testing.T) {
	t.Parallel()

	t.Run("success with code and state", func(t *testing.T) {
		callbackURL := "https://app.example.com/callback?code=auth-code-123&state=random-state"
		code, state, err := ParseAuthorizationCallback(callbackURL)
		require.NoError(t, err)
		require.Equal(t, "auth-code-123", code)
		require.Equal(t, "random-state", state)
	})

	t.Run("success with code only", func(t *testing.T) {
		callbackURL := "https://app.example.com/callback?code=auth-code-456"
		code, state, err := ParseAuthorizationCallback(callbackURL)
		require.NoError(t, err)
		require.Equal(t, "auth-code-456", code)
		require.Empty(t, state)
	})

	t.Run("error response", func(t *testing.T) {
		callbackURL := "https://app.example.com/callback?error=access_denied&error_description=User+denied+access"
		_, _, err := ParseAuthorizationCallback(callbackURL)
		require.Error(t, err)
		require.Contains(t, err.Error(), "access_denied")
		require.Contains(t, err.Error(), "User denied access")
	})

	t.Run("missing code", func(t *testing.T) {
		callbackURL := "https://app.example.com/callback?state=random-state"
		_, _, err := ParseAuthorizationCallback(callbackURL)
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing authorization code")
	})

	t.Run("invalid URL", func(t *testing.T) {
		callbackURL := "://invalid-url"
		_, _, err := ParseAuthorizationCallback(callbackURL)
		require.Error(t, err)
		require.Contains(t, strings.ToLower(err.Error()), "parse")
	})
}
