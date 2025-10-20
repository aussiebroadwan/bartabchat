package auth_test

import (
	"testing"

	"github.com/aussiebroadwan/bartab/pkg/authsdk"
	"github.com/aussiebroadwan/bartab/pkg/jwtx"
	"github.com/stretchr/testify/require"
)

// TestJWKSVerification verifies that tokens issued by the service can be verified
// using the JWKS endpoint. This tests the complete flow of:
// 1. Bootstrap the service
// 2. Login with admin user
// 3. Fetch JWKS
// 4. Verify the access token using the JWKS
func TestJWKSVerification(t *testing.T) {
	baseURL, cleanup := setupAuthContainer(t)
	defer cleanup()

	client := authsdk.NewSDKClient(baseURL)

	// 1. Bootstrap the service
	clientID, clientSecret, _ := bootstrapService(t, client)
	t.Logf("Bootstrap successful, client ID: %s", clientID)

	// 2. Login with admin user to get an access token
	session := performLogin(t, client, clientID, clientSecret, adminUsername, adminPassword)
	accessToken := session.AccessToken()
	t.Logf("Login successful, got access token")

	// 3. Fetch the JWKS from the service
	jwksResp, err := client.GetJWKS(t.Context())

	require.NoError(t, err, "Should fetch JWKS successfully")
	require.NotNil(t, jwksResp)
	require.NotEmpty(t, jwksResp.Keys, "JWKS should contain at least one key")

	t.Logf("JWKS fetched successfully with %d key(s)", len(jwksResp.Keys))

	// 4. Create a KeySet and load the JWKS into it
	keySet := jwtx.NewKeySet()
	jwks := jwtx.JWKS(*jwksResp)
	err = keySet.ResetFromJWKS(jwks)

	require.NoError(t, err, "Should load JWKS into KeySet")

	t.Logf("KeySet loaded with JWKS")

	// 5. Create a verifier based on the algorithm in the JWKS
	// Default algorithm is RS256, but we'll check the JWKS to be safe
	var verifier jwtx.Verifier
	algorithm := jwks.Keys[0].Alg

	// The issuer is "bartab-auth" by default (see cmd/auth/config.go)
	issuer := "bartab-auth"
	audience := []string{} // No audience validation for now

	switch algorithm {
	case "RS256":
		verifier = jwtx.NewCommonRS256(keySet, issuer, audience)
		t.Logf("Created RS256 verifier")
	case "EdDSA":
		verifier = jwtx.NewCommonEdDSA(keySet, issuer, audience)
		t.Logf("Created EdDSA verifier")
	case "ES256":
		verifier = jwtx.NewCommonES256(keySet, issuer, audience)
		t.Logf("Created ES256 verifier")
	default:
		t.Fatalf("Unsupported algorithm in JWKS: %s", algorithm)
	}

	// 6. Verify the access token
	claims, err := verifier.Verify(accessToken)
	require.NoError(t, err, "Should verify access token successfully")

	// 7. Assert the claims are what we expect
	require.NotEmpty(t, claims.Subject, "Subject should contain user ID")
	require.Equal(t, adminUsername, claims.Username, "Username claim should match")
	require.Equal(t, issuer, claims.Issuer, "Issuer should match")
	require.NotEmpty(t, claims.ID, "JTI (token ID) should not be empty")
	require.NotZero(t, claims.ExpiresAt, "Token should have expiration")
	require.NotEmpty(t, claims.Scopes, "Token should have scopes")
	require.Contains(t, claims.AMR, "pwd", "AMR should contain 'pwd' for password authentication")

	t.Logf("Token verified successfully!")
	t.Logf("  Subject: %s", claims.Subject)
	t.Logf("  Username: %s", claims.Username)
	t.Logf("  Issuer: %s", claims.Issuer)
	t.Logf("  Scopes: %v", claims.Scopes)
	t.Logf("  AMR: %v", claims.AMR)
	t.Logf("  Session ID: %s", claims.SID)
	t.Logf("  JTI: %s", claims.ID)
	t.Logf("  Expires At: %s", claims.ExpiresAt.Time)

	// 8. Print the PEM format for use with jwt.io
	pemStr, err := jwks.Keys[0].PEM()
	require.NoError(t, err, "Should convert JWK to PEM")

	t.Logf("\nPublic Key (PEM format for jwt.io):\n%s", pemStr)
	t.Logf("\nAccess Token:\n%s", accessToken)
}

// TestJWKSFormat verifies the JWKS endpoint returns properly formatted keys.
// This helps debug why jwt.io might not be working - it's very picky about format.
func TestJWKSFormat(t *testing.T) {
	baseURL, cleanup := setupAuthContainer(t)
	defer cleanup()

	client := authsdk.NewSDKClient(baseURL)

	// Bootstrap the service to ensure keys are generated
	clientID, _, _ := bootstrapService(t, client)
	t.Logf("Bootstrap successful, client ID: %s", clientID)

	// Fetch the JWKS
	jwksResp, err := client.GetJWKS(t.Context())

	require.NoError(t, err, "Should fetch JWKS successfully")
	require.NotNil(t, jwksResp)
	require.NotEmpty(t, jwksResp.Keys, "JWKS should contain at least one key")

	// Check the first key's format
	key := jwksResp.Keys[0]
	t.Logf("JWKS Key Details:")
	t.Logf("  Key Type (kty): %s", key.Kty)
	t.Logf("  Algorithm (alg): %s", key.Alg)
	t.Logf("  Use (use): %s", key.Use)
	t.Logf("  Key ID (kid): %s", key.Kid)

	// Required fields for all keys
	require.NotEmpty(t, key.Kty, "kty (key type) must be present")
	require.NotEmpty(t, key.Alg, "alg (algorithm) must be present")
	require.NotEmpty(t, key.Kid, "kid (key ID) must be present")
	require.Equal(t, "sig", key.Use, "use should be 'sig' for signature keys")

	// Algorithm-specific fields
	switch key.Alg {
	case "RS256":
		require.Equal(t, "RSA", key.Kty, "RS256 keys should have kty=RSA")
		require.NotEmpty(t, key.N, "RSA keys must have 'n' (modulus)")
		require.NotEmpty(t, key.E, "RSA keys must have 'e' (exponent)")

		t.Logf("  RSA Modulus length: %d characters", len(key.N))
		t.Logf("  RSA Exponent: %s", key.E)

	case "EdDSA":
		require.Equal(t, "OKP", key.Kty, "EdDSA keys should have kty=OKP")
		require.Equal(t, "Ed25519", key.Crv, "EdDSA keys should have crv=Ed25519")
		require.NotEmpty(t, key.X, "EdDSA keys must have 'x' (public key)")

		t.Logf("  Curve: %s", key.Crv)
		t.Logf("  X coordinate length: %d characters", len(key.X))

	case "ES256":
		require.Equal(t, "EC", key.Kty, "ES256 keys should have kty=EC")
		require.Equal(t, "P-256", key.Crv, "ES256 keys should have crv=P-256")
		require.NotEmpty(t, key.X, "EC keys must have 'x' coordinate")
		require.NotEmpty(t, key.Y, "EC keys must have 'y' coordinate")

		t.Logf("  Curve: %s", key.Crv)
		t.Logf("  X coordinate length: %d characters", len(key.X))
		t.Logf("  Y coordinate length: %d characters", len(key.Y))

	default:
		t.Fatalf("Unknown algorithm: %s", key.Alg)
	}

	// Print the PEM format for debugging
	pemStr, err := key.PEM()
	require.NoError(t, err, "Should convert JWK to PEM")

	t.Logf("\nPublic Key (PEM format):\n%s", pemStr)
}
