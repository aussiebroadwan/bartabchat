package service

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"testing"
	"time"

	"github.com/aussiebroadwan/bartab/internal/auth/domain"
	"github.com/aussiebroadwan/bartab/internal/auth/store/drivers/sqlite"
	"github.com/aussiebroadwan/bartab/pkg/cryptox"
	"github.com/aussiebroadwan/bartab/pkg/idx"
	"github.com/aussiebroadwan/bartab/pkg/jwtx"
	"github.com/stretchr/testify/require"
)

func TestValidatePKCE(t *testing.T) {
	t.Parallel()

	confidential := domain.Client{SecretHash: "argon2:dummy"}
	public := domain.Client{}

	t.Run("public clients require challenge", func(t *testing.T) {
		_, _, err := validatePKCE("", "", public)
		require.ErrorIs(t, err, ErrInvalidRequest)
	})

	t.Run("confidential clients may omit challenge", func(t *testing.T) {
		challenge, method, err := validatePKCE("", "", confidential)
		require.Nil(t, err)
		require.Empty(t, challenge)
		require.Empty(t, method)
	})

	t.Run("defaults to S256 when method omitted", func(t *testing.T) {
		challenge, method, err := validatePKCE("pkce-challenge", "", public)
		require.Nil(t, err)
		require.Equal(t, "pkce-challenge", challenge)
		require.Equal(t, "S256", method)
	})

	t.Run("accepts case-insensitive methods", func(t *testing.T) {
		challenge, method, err := validatePKCE("abc", "plain", public)
		require.Nil(t, err)
		require.Equal(t, "abc", challenge)
		require.Equal(t, "plain", method)

		challenge, method, err = validatePKCE("xyz", "s256", public)
		require.Nil(t, err)
		require.Equal(t, "xyz", challenge)
		require.Equal(t, "S256", method)
	})

	t.Run("rejects unsupported methods", func(t *testing.T) {
		_, _, err := validatePKCE("abc", "S123", public)
		require.ErrorIs(t, err, ErrInvalidRequest)
	})
}

func TestVerifyCodeVerifier(t *testing.T) {
	t.Parallel()

	t.Run("plain verifier must match challenge", func(t *testing.T) {
		require.True(t, verifyCodeVerifier("verifier", "plain", "verifier"))
		require.False(t, verifyCodeVerifier("verifier", "plain", "other"))
	})

	t.Run("S256 verifier computes hash", func(t *testing.T) {
		verifier := "example-verifier"
		sum := sha256.Sum256([]byte(verifier))
		challenge := base64.RawURLEncoding.EncodeToString(sum[:])

		require.True(t, verifyCodeVerifier(challenge, "S256", verifier))
		require.False(t, verifyCodeVerifier(challenge, "S256", "wrong"))
	})

	t.Run("empty challenge accepts any verifier", func(t *testing.T) {
		require.True(t, verifyCodeVerifier("", "S256", ""))
		require.True(t, verifyCodeVerifier("", "", "anything"))
	})

	t.Run("missing verifier rejected when challenge present", func(t *testing.T) {
		sum := sha256.Sum256([]byte("data"))
		challenge := base64.RawURLEncoding.EncodeToString(sum[:])
		require.False(t, verifyCodeVerifier(challenge, "S256", ""))
	})
}

func TestIntersectThreeWay(t *testing.T) {
	t.Parallel()

	t.Run("returns intersection without duplicates", func(t *testing.T) {
		requested := []string{"profile:read", "profile:read", "admin:write", "unknown"}
		clientScopes := []string{"profile:read", "admin:write"}
		roleScopes := []string{"profile:read", "audit:read"}

		result := intersectThreeWay(requested, clientScopes, roleScopes)
		require.Equal(t, []string{"profile:read"}, result)
	})

	t.Run("returns empty slice when no overlap", func(t *testing.T) {
		requested := []string{"profile:read"}
		clientScopes := []string{"admin:write"}
		roleScopes := []string{"audit:read"}

		result := intersectThreeWay(requested, clientScopes, roleScopes)
		require.Empty(t, result)
	})
}

func TestExchangeAuthorizationCodeEnforcesSingleUse(t *testing.T) {
	ctx := context.Background()

	store, err := sqlite.NewStore(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	require.NoError(t, store.ApplyMigrations())

	// Create supporting data: role, user, client, and authorization code.
	role := domain.Role{ID: idx.New().String(), Name: "admin", Scopes: []string{"profile:read", "admin:write"}, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	require.NoError(t, store.Roles().CreateRole(ctx, role))

	user := domain.User{
		ID:            idx.New().String(),
		Username:      "alice",
		PreferredName: "Alice",
		PasswordHash:  "hash",
		RoleID:        role.ID,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}
	require.NoError(t, store.Users().CreateUser(ctx, user))

	client := domain.Client{ID: idx.New().String(), Name: "web-app", SecretHash: "", Scopes: []string{"profile:read", "admin:write"}, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	require.NoError(t, store.Clients().CreateClient(ctx, client))

	verifier := "example-code-verifier"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	code := "authorization-code"
	record := domain.AuthorizationCode{
		ID:                  idx.New().String(),
		UserID:              user.ID,
		ClientID:            client.ID,
		CodeHash:            cryptox.FingerprintToken(code),
		RedirectURI:         "https://app.example/callback",
		Scopes:              []string{"profile:read", "admin:write"},
		SessionID:           idx.New().String(),
		AMR:                 []string{jwtx.AMRPassword},
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
		ExpiresAt:           time.Now().Add(5 * time.Minute),
		CreatedAt:           time.Now(),
	}
	require.NoError(t, store.AuthorizationCodes().CreateAuthorizationCode(ctx, record))

	keyManager, err := jwtx.NewEphemeralKeyManager(jwtx.KeyManagerOptions{
		Algorithm: jwtx.AlgorithmEdDSA,
		Issuer:    "test-issuer",
		NumKeys:   1,
	})
	require.NoError(t, err)

	svc := &TokenService{
		KeyManager: keyManager,
		Store:      store,
		Issuer:     "test-issuer",
		AccessTTL:  time.Minute,
		RefreshTTL: time.Hour,
	}

	pair, err := svc.ExchangeAuthorizationCode(ctx, client.ID, "", code, record.RedirectURI, verifier)
	require.NoError(t, err)
	require.NotNil(t, pair)
	require.NotEmpty(t, pair.AccessToken)
	require.NotEmpty(t, pair.RefreshToken)

	_, err = svc.ExchangeAuthorizationCode(ctx, client.ID, "", code, record.RedirectURI, verifier)
	require.ErrorIs(t, err, ErrInvalidGrant)
}
