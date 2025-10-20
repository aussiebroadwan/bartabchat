package cryptox

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGenerateToken(t *testing.T) {
	tests := []struct {
		name string
		size int
		want string
	}{
		{"128-bit token", TokenSize128, ""},
		{"256-bit token", TokenSize256, ""},
		{"512-bit token", TokenSize512, ""},
		{"custom size", 24, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := GenerateToken(tt.size)
			require.NoError(t, err)
			require.NotEmpty(t, token)

			// Verify token is unique (generate another and compare)
			token2, err := GenerateToken(tt.size)
			require.NoError(t, err)
			require.NotEqual(t, token, token2, "tokens should be unique")
		})
	}
}

func TestGenerateToken_InvalidSize(t *testing.T) {
	tests := []struct {
		name string
		size int
	}{
		{"zero size", 0},
		{"negative size", -1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := GenerateToken(tt.size)
			require.Error(t, err)
			require.Empty(t, token)
		})
	}
}

func TestMustGenerateToken(t *testing.T) {
	token := MustGenerateToken(TokenSize256)
	require.NotEmpty(t, token)
}

func TestMustGenerateToken_Panics(t *testing.T) {
	require.Panics(t, func() {
		MustGenerateToken(0)
	})
}

func TestFingerprintToken(t *testing.T) {
	token1 := "test-token-1"
	token2 := "test-token-2"

	fp1a := FingerprintToken(token1)
	fp1b := FingerprintToken(token1)
	fp2 := FingerprintToken(token2)

	// Fingerprint should be deterministic
	require.Equal(t, fp1a, fp1b, "fingerprint should be deterministic")

	// Different tokens should have different fingerprints
	require.NotEqual(t, fp1a, fp2, "different tokens should have different fingerprints")

	// Fingerprint should be base64url encoded SHA-256 (43 chars)
	require.Len(t, fp1a, 43, "SHA-256 base64url should be 43 chars")
}

func TestGenerateToken_EntropyQuality(t *testing.T) {
	// Generate multiple tokens and ensure they're all different
	const count = 100
	tokens := make(map[string]bool, count)

	for range count {
		token, err := GenerateToken(TokenSize256)
		require.NoError(t, err)
		require.NotContains(t, tokens, token, "duplicate token generated")
		tokens[token] = true
	}
}
