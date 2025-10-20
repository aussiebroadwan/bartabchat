package auth_test

import (
	"encoding/json"
	"testing"

	"github.com/aussiebroadwan/bartab/pkg/authsdk"
	"github.com/stretchr/testify/require"
)

// TestLivezEndpoint verifies the liveness check endpoint works before bootstrap.
func TestLivezEndpoint(t *testing.T) {
	baseURL, cleanup := setupAuthContainer(t)
	defer cleanup()

	client := authsdk.NewSDKClient(baseURL)

	health, err := client.GetLiveness(t.Context())
	assertHealthy(t, health, err)

	t.Logf("Livez endpoint is healthy")
}

// TestReadyzEndpoint verifies the readiness check endpoint works before bootstrap.
func TestReadyzEndpoint(t *testing.T) {
	baseURL, cleanup := setupAuthContainer(t)
	defer cleanup()

	client := authsdk.NewSDKClient(baseURL)

	health, err := client.GetReadiness(t.Context())
	assertHealthy(t, health, err)

	t.Logf("Readyz endpoint is healthy")
}

// TestJWKSEndpoint verifies JWKS are available before bootstrap.
func TestJWKSEndpoint(t *testing.T) {
	baseURL, cleanup := setupAuthContainer(t)
	defer cleanup()

	client := authsdk.NewSDKClient(baseURL)

	jwks, err := client.GetJWKS(t.Context())

	require.NoError(t, err)
	require.NotNil(t, jwks)
	require.NotEmpty(t, jwks.Keys, "JWKS should contain at least one key")

	t.Logf("JWKS endpoint returned %d key(s)", len(jwks.Keys))

	for _, key := range jwks.Keys {
		t.Logf("Key ID: %s, Algorithm: %s, Use: %s", key.Kid, key.Alg, key.Use)
		keyJSON, _ := json.Marshal(key)
		t.Logf("Key JSON: %s", keyJSON)
	}
}
