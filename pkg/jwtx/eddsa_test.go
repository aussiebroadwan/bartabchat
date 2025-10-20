package jwtx_test

import (
	"testing"
	"time"

	"github.com/aussiebroadwan/bartab/pkg/cryptox"
	"github.com/aussiebroadwan/bartab/pkg/jwtx"
	"github.com/stretchr/testify/require"
)

func TestEdDSASignAndVerify(t *testing.T) {
	// Generate Ed25519 keypair
	pemKey, err := cryptox.GenerateEd25519Key()
	require.NoError(t, err)

	kid := "test-key-eddsa"

	// Create signer
	signer, err := jwtx.NewSignerEdDSA(kid, pemKey)
	require.NoError(t, err)
	require.NotNil(t, signer)
	require.NoError(t, signer.Validate())
	require.Equal(t, "EdDSA", signer.Alg())
	require.Equal(t, kid, signer.KID())

	// Build claims using helper function
	now := time.Now().UTC()
	claims := jwtx.NewAccessClaims(
		"user-456",       // subject
		"session-eddsa1", // session ID
		[]string{"profile:read", "profile:write"}, // scopes
		[]string{"pwd"}, // AMR
		5*time.Minute,   // TTL
		exampleIssuer,   // issuer
		[]string{"api"}, // audience
		"eddsauser",     // username
		"EdDSA User",    // preferred name
		now,             // issued at time
	)

	// Sign token
	token, err := signer.Sign(claims)
	require.NoError(t, err)
	require.NotEmpty(t, token)

	// Build KeySet for verification
	keyset := jwtx.NewKeySet()
	require.NoError(t, keyset.AddSigner(signer))

	// Verify the keyset has the right key
	jwks := keyset.PublicJWKS()
	require.Len(t, jwks.Keys, 1)
	require.Equal(t, "OKP", jwks.Keys[0].Kty)
	require.Equal(t, "Ed25519", jwks.Keys[0].Crv)
	require.NotEmpty(t, jwks.Keys[0].X)

	// Create verifier
	verifier := jwtx.NewVerifierEdDSA(keyset, exampleIssuer, []string{"api"})

	// Verify token
	parsedClaims, err := verifier.Verify(token)
	require.NoError(t, err)
	require.NotNil(t, parsedClaims)

	require.Equal(t, claims.Issuer, parsedClaims.Issuer)
	require.Equal(t, claims.Subject, parsedClaims.Subject)
	require.ElementsMatch(t, claims.Audience, parsedClaims.Audience)
	require.ElementsMatch(t, claims.Scopes, parsedClaims.Scopes)
	require.ElementsMatch(t, claims.AMR, parsedClaims.AMR)
	require.Equal(t, claims.SID, parsedClaims.SID)
	require.Equal(t, claims.Username, parsedClaims.Username)
	require.Equal(t, claims.PreferredName, parsedClaims.PreferredName)
	require.NotEmpty(t, parsedClaims.ID) // JTI should be set
}

func TestEdDSAVerifyFailsForWrongIssuer(t *testing.T) {
	// Generate Ed25519 keypair
	pemKey, err := cryptox.GenerateEd25519Key()
	require.NoError(t, err)

	// Create signer
	signer, err := jwtx.NewSignerEdDSA("k1", pemKey)
	require.NoError(t, err)

	// Build claims using helper function
	now := time.Now().UTC()
	claims := jwtx.NewAccessClaims(
		"user-789",
		"session-wrong",
		nil,
		nil,
		1*time.Minute,
		exampleIssuer,
		nil,
		"",
		"",
		now,
	)

	// Sign token
	token, err := signer.Sign(claims)
	require.NoError(t, err)

	// Build KeySet for verification
	keyset := jwtx.NewKeySet()
	require.NoError(t, keyset.AddSigner(signer))

	// Create verifier with wrong expected issuer
	verifier := jwtx.NewVerifierEdDSA(keyset, "wrong-issuer", []string{"api"})

	// Verify token
	_, err = verifier.Verify(token)
	require.ErrorIs(t, err, jwtx.ErrIssuer)
}

func TestEdDSAVerifyFailsForUnknownKey(t *testing.T) {
	// Generate two Ed25519 keypairs
	pemKey1, _ := cryptox.GenerateEd25519Key()
	signer1, _ := jwtx.NewSignerEdDSA("key1", pemKey1)

	pemKey2, _ := cryptox.GenerateEd25519Key()
	signer2, _ := jwtx.NewSignerEdDSA("key2", pemKey2)

	// Token signed with key1 using helper function
	now := time.Now().UTC()
	claims := jwtx.NewAccessClaims(
		"user-unknown", "session-key", nil, nil,
		1*time.Minute, exampleIssuer, nil, "", "", now,
	)
	token, _ := signer1.Sign(claims)

	// Keyset only contains key2
	keyset := jwtx.NewKeySet()
	require.NoError(t, keyset.AddSigner(signer2))

	verifier := jwtx.NewVerifierEdDSA(keyset, exampleIssuer, nil)

	_, err := verifier.Verify(token)
	require.ErrorIs(t, err, jwtx.ErrNoKey)
}

func TestEdDSAVerifyFailsForRS256Token(t *testing.T) {
	// Create an RS256 signer
	pemKey, err := cryptox.GenerateRSAKey(2048)
	require.NoError(t, err)

	rs256Signer, err := jwtx.NewSignerRS256("rsa-key", pemKey)
	require.NoError(t, err)

	// Sign a token with RS256 using helper function
	now := time.Now().UTC()
	claims := jwtx.NewAccessClaims(
		"user-rsa", "session-rsa", nil, nil,
		1*time.Minute, exampleIssuer, nil, "", "", now,
	)
	token, err := rs256Signer.Sign(claims)
	require.NoError(t, err)

	// Create an EdDSA verifier
	eddsaPemKey, err := cryptox.GenerateEd25519Key()
	require.NoError(t, err)
	eddsaSigner, err := jwtx.NewSignerEdDSA("eddsa-key", eddsaPemKey)
	require.NoError(t, err)

	keyset := jwtx.NewKeySet()
	require.NoError(t, keyset.AddSigner(eddsaSigner))

	verifier := jwtx.NewVerifierEdDSA(keyset, exampleIssuer, nil)

	// Should fail because the token is RS256, not EdDSA
	_, err = verifier.Verify(token)
	require.Error(t, err)
}

func TestEdDSAValidateFailsForInvalidKey(t *testing.T) {
	// Try to create a signer with invalid PEM
	_, err := jwtx.NewSignerEdDSA("test", []byte("not-a-pem-key"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid PEM")
}

func TestEdDSACommonVerifierAdapter(t *testing.T) {
	// Generate Ed25519 keypair
	pemKey, err := cryptox.GenerateEd25519Key()
	require.NoError(t, err)

	// Create signer
	signer, err := jwtx.NewSignerEdDSA("test-key", pemKey)
	require.NoError(t, err)

	// Build claims using helper function
	now := time.Now().UTC()
	claims := jwtx.NewAccessClaims(
		"user-123",
		"session-adapter",
		[]string{"test:read"},
		nil,
		1*time.Minute,
		exampleIssuer,
		nil,
		"adapteruser",
		"Adapter User",
		now,
	)

	// Sign token
	token, err := signer.Sign(claims)
	require.NoError(t, err)

	// Build KeySet
	keyset := jwtx.NewKeySet()
	require.NoError(t, keyset.AddSigner(signer))

	// Use the common verifier adapter
	verifier := jwtx.NewCommonEdDSA(keyset, exampleIssuer, nil)

	// Verify token - note this returns Claims by value, not pointer
	parsedClaims, err := verifier.Verify(token)
	require.NoError(t, err)
	require.Equal(t, claims.Issuer, parsedClaims.Issuer)
	require.Equal(t, claims.Subject, parsedClaims.Subject)
	require.ElementsMatch(t, claims.Scopes, parsedClaims.Scopes)
}
