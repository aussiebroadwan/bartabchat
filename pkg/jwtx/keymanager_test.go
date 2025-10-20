package jwtx_test

import (
	"testing"
	"time"

	"github.com/aussiebroadwan/bartab/pkg/jwtx"
	"github.com/stretchr/testify/require"
)

func TestNewEphemeralKeyManager_AllAlgorithms(t *testing.T) {
	tests := []struct {
		name      string
		algorithm string
		rsaBits   int
	}{
		{
			name:      "RS256 with default bits",
			algorithm: jwtx.AlgorithmRS256,
			rsaBits:   0, // Will use default 4096
		},
		{
			name:      "RS256 with 2048 bits",
			algorithm: jwtx.AlgorithmRS256,
			rsaBits:   2048,
		},
		{
			name:      "ES256",
			algorithm: jwtx.AlgorithmES256,
			rsaBits:   0, // Not used for ES256
		},
		{
			name:      "EdDSA",
			algorithm: jwtx.AlgorithmEdDSA,
			rsaBits:   0, // Not used for EdDSA
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			km, err := jwtx.NewEphemeralKeyManager(jwtx.KeyManagerOptions{
				Algorithm: tt.algorithm,
				Issuer:    "test-issuer",
				Audience:  []string{"test-audience"},
				RSABits:   tt.rsaBits,
				NumKeys:   1, // Use single key for backward compatibility tests
			})

			require.NoError(t, err)
			require.NotNil(t, km)
			require.NotNil(t, km.Signer)
			require.NotNil(t, km.Verifier)
			require.NotNil(t, km.KeySet)
			require.Equal(t, tt.algorithm, km.Algorithm())
			require.True(t, km.IsReady())
			require.Equal(t, 1, km.NumSigners())
		})
	}
}

func TestKeyManager_SignAndVerifyRoundTrip(t *testing.T) {
	tests := []struct {
		name      string
		algorithm string
	}{
		{"RS256", jwtx.AlgorithmRS256},
		{"ES256", jwtx.AlgorithmES256},
		{"EdDSA", jwtx.AlgorithmEdDSA},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create key manager with single key for predictable testing
			km, err := jwtx.NewEphemeralKeyManager(jwtx.KeyManagerOptions{
				Algorithm: tt.algorithm,
				Issuer:    "test-issuer",
				Audience:  []string{"test-audience"},
				NumKeys:   1, // Single key mode for deterministic behavior
			})
			require.NoError(t, err)

			// Create test claims
			now := time.Now().UTC()
			claims := jwtx.NewAccessClaims(
				"user-123",
				"session-abc",
				[]string{"read", "write"},
				[]string{"pwd"},
				5*time.Minute,
				"test-issuer",
				[]string{"test-audience"},
				"testuser",
				"Test User",
				now,
			)

			// Sign token using GetSigner() for forward compatibility
			signer := km.GetSigner()
			require.NotNil(t, signer)
			token, err := signer.Sign(claims)
			require.NoError(t, err)
			require.NotEmpty(t, token)

			// Verify token
			parsedClaims, err := km.Verifier.Verify(token)
			require.NoError(t, err)
			require.NotNil(t, parsedClaims)

			// Validate claims
			require.Equal(t, claims.Subject, parsedClaims.Subject)
			require.Equal(t, claims.Issuer, parsedClaims.Issuer)
			require.ElementsMatch(t, claims.Audience, parsedClaims.Audience)
			require.ElementsMatch(t, claims.Scopes, parsedClaims.Scopes)
			require.ElementsMatch(t, claims.AMR, parsedClaims.AMR)
			require.Equal(t, claims.SID, parsedClaims.SID)
			require.Equal(t, claims.Username, parsedClaims.Username)
			require.Equal(t, claims.PreferredName, parsedClaims.PreferredName)
		})
	}
}

func TestNewEphemeralKeyManager_ErrorCases(t *testing.T) {
	tests := []struct {
		name        string
		opts        jwtx.KeyManagerOptions
		expectedErr string
	}{
		{
			name: "missing Issuer",
			opts: jwtx.KeyManagerOptions{
				Algorithm: jwtx.AlgorithmRS256,
			},
			expectedErr: "Issuer is required",
		},
		{
			name: "unsupported algorithm",
			opts: jwtx.KeyManagerOptions{
				Algorithm: "HS256",
				Issuer:    "test-issuer",
			},
			expectedErr: "unsupported algorithm",
		},
		{
			name: "invalid RSA bits (too small)",
			opts: jwtx.KeyManagerOptions{
				Algorithm: jwtx.AlgorithmRS256,
				Issuer:    "test-issuer",
				RSABits:   1024,
				NumKeys:   1,
			},
			expectedErr: "at least 2048 bits",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			km, err := jwtx.NewEphemeralKeyManager(tt.opts)
			require.Error(t, err)
			require.Nil(t, km)
			require.Contains(t, err.Error(), tt.expectedErr)
		})
	}
}

func TestKeyManager_IsReady(t *testing.T) {
	km, err := jwtx.NewEphemeralKeyManager(jwtx.KeyManagerOptions{
		Algorithm: jwtx.AlgorithmEdDSA,
		Issuer:    "test-issuer",
		NumKeys:   1,
	})
	require.NoError(t, err)
	require.True(t, km.IsReady())

	// Create empty KeySet
	emptyKS := jwtx.NewKeySet()
	require.False(t, emptyKS.IsReady())
}

func TestKeyManager_DifferentAudiences(t *testing.T) {
	// Test with nil audience (no validation)
	km, err := jwtx.NewEphemeralKeyManager(jwtx.KeyManagerOptions{
		Algorithm: jwtx.AlgorithmES256,
		Issuer:    "test-issuer",
		Audience:  nil, // No audience validation
		NumKeys:   1,
	})
	require.NoError(t, err)
	require.NotNil(t, km)

	// Test with multiple audiences
	km2, err := jwtx.NewEphemeralKeyManager(jwtx.KeyManagerOptions{
		Algorithm: jwtx.AlgorithmES256,
		Issuer:    "test-issuer",
		Audience:  []string{"aud1", "aud2", "aud3"},
		NumKeys:   1,
	})
	require.NoError(t, err)
	require.NotNil(t, km2)
}

func TestKeyManager_MultiKeyMode(t *testing.T) {
	// Test multi-key mode with default (3 keys)
	km, err := jwtx.NewEphemeralKeyManager(jwtx.KeyManagerOptions{
		Algorithm: jwtx.AlgorithmEdDSA,
		Issuer:    "test-issuer",
		Audience:  []string{"test-audience"},
		// NumKeys not specified, should default to 3
	})
	require.NoError(t, err)
	require.NotNil(t, km)
	require.Equal(t, 3, km.NumSigners())

	// Verify JWKS contains all 3 keys
	jwks := km.KeySet.PublicJWKS()
	require.NotNil(t, jwks)
	require.Len(t, jwks.Keys, 3)

	// Verify all keys have different kid values
	kids := make(map[string]bool)
	for _, jwk := range jwks.Keys {
		require.NotEmpty(t, jwk.Kid)
		require.False(t, kids[jwk.Kid], "duplicate kid found: %s", jwk.Kid)
		kids[jwk.Kid] = true
	}

	// Test signing with GetSigner() and verify with all keys in JWKS
	now := time.Now().UTC()
	for range 10 {
		claims := jwtx.NewAccessClaims(
			"user-123",
			"session-abc",
			[]string{"read", "write"},
			[]string{"pwd"},
			5*time.Minute,
			"test-issuer",
			[]string{"test-audience"},
			"testuser",
			"Test User",
			now,
		)

		signer := km.GetSigner()
		require.NotNil(t, signer)
		token, err := signer.Sign(claims)
		require.NoError(t, err)
		require.NotEmpty(t, token)

		// Verify token can be verified (verifier has all keys)
		parsedClaims, err := km.Verifier.Verify(token)
		require.NoError(t, err)
		require.NotNil(t, parsedClaims)
		require.Equal(t, claims.Subject, parsedClaims.Subject)
	}
}

func TestKeyManager_CustomNumKeys(t *testing.T) {
	tests := []struct {
		name     string
		numKeys  int
		expected int
	}{
		{"explicit 2 keys", 2, 2},
		{"explicit 5 keys", 5, 5},
		{"explicit 1 key", 1, 1},
		{"max capped at 10", 15, 10},
		{"min capped at 1", 0, 3}, // 0 defaults to 3
		{"negative defaults to 3", -1, 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			km, err := jwtx.NewEphemeralKeyManager(jwtx.KeyManagerOptions{
				Algorithm: jwtx.AlgorithmEdDSA,
				Issuer:    "test-issuer",
				NumKeys:   tt.numKeys,
			})
			require.NoError(t, err)
			require.Equal(t, tt.expected, km.NumSigners())

			// Verify JWKS has correct number of keys
			jwks := km.KeySet.PublicJWKS()
			require.Len(t, jwks.Keys, tt.expected)
		})
	}
}
