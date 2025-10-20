package jwtx_test

import (
	"testing"
	"time"

	"github.com/aussiebroadwan/bartab/pkg/cryptox"
	"github.com/aussiebroadwan/bartab/pkg/jwtx"
	"github.com/stretchr/testify/require"
)

func TestES256SignAndVerify(t *testing.T) {
	// Generate ECDSA P-256 keypair
	pemKey, err := cryptox.GenerateES256Key()
	require.NoError(t, err)

	kid := "test-key-es256"

	// Create signer
	signer, err := jwtx.NewSignerES256(kid, pemKey)
	require.NoError(t, err)
	require.NotNil(t, signer)
	require.NoError(t, signer.Validate())
	require.Equal(t, "ES256", signer.Alg())
	require.Equal(t, kid, signer.KID())

	// Build claims using helper function
	now := time.Now().UTC()
	claims := jwtx.NewAccessClaims(
		"user-789",       // subject
		"session-es256",  // session ID
		[]string{"api:read", "api:write"}, // scopes
		[]string{"pwd"},  // AMR
		10*time.Minute,   // TTL
		exampleIssuer,    // issuer
		[]string{"api"},  // audience
		"es256user",      // username
		"ES256 User",     // preferred name
		now,              // issued at time
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
	require.Equal(t, "EC", jwks.Keys[0].Kty)
	require.Equal(t, "P-256", jwks.Keys[0].Crv)
	require.NotEmpty(t, jwks.Keys[0].X)
	require.NotEmpty(t, jwks.Keys[0].Y)

	// Create verifier
	verifier := jwtx.NewVerifierES256(keyset, exampleIssuer, []string{"api"})

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

func TestES256VerifyFailsForWrongIssuer(t *testing.T) {
	// Generate ECDSA P-256 keypair
	pemKey, err := cryptox.GenerateES256Key()
	require.NoError(t, err)

	// Create signer
	signer, err := jwtx.NewSignerES256("k1", pemKey)
	require.NoError(t, err)

	// Build claims using helper function
	now := time.Now().UTC()
	claims := jwtx.NewAccessClaims(
		"user-999",
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
	verifier := jwtx.NewVerifierES256(keyset, "wrong-issuer", []string{"api"})

	// Verify token
	_, err = verifier.Verify(token)
	require.ErrorIs(t, err, jwtx.ErrIssuer)
}

func TestES256VerifyFailsForUnknownKey(t *testing.T) {
	// Generate two ECDSA P-256 keypairs
	pemKey1, _ := cryptox.GenerateES256Key()
	signer1, _ := jwtx.NewSignerES256("key1", pemKey1)

	pemKey2, _ := cryptox.GenerateES256Key()
	signer2, _ := jwtx.NewSignerES256("key2", pemKey2)

	// Token signed with key1 using helper function
	now := time.Now().UTC()
	claims := jwtx.NewAccessClaims(
		"user-unknown", "session-es256-key", nil, nil,
		1*time.Minute, exampleIssuer, nil, "", "", now,
	)
	token, _ := signer1.Sign(claims)

	// Keyset only contains key2
	keyset := jwtx.NewKeySet()
	require.NoError(t, keyset.AddSigner(signer2))

	verifier := jwtx.NewVerifierES256(keyset, exampleIssuer, nil)

	_, err := verifier.Verify(token)
	require.ErrorIs(t, err, jwtx.ErrNoKey)
}

func TestES256VerifyFailsForRS256Token(t *testing.T) {
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

	// Create an ES256 verifier
	es256PemKey, err := cryptox.GenerateES256Key()
	require.NoError(t, err)
	es256Signer, err := jwtx.NewSignerES256("es256-key", es256PemKey)
	require.NoError(t, err)

	keyset := jwtx.NewKeySet()
	require.NoError(t, keyset.AddSigner(es256Signer))

	verifier := jwtx.NewVerifierES256(keyset, exampleIssuer, nil)

	// Should fail because the token is RS256, not ES256
	_, err = verifier.Verify(token)
	require.Error(t, err)
}

func TestES256VerifyFailsForEdDSAToken(t *testing.T) {
	// Create an EdDSA signer
	pemKey, err := cryptox.GenerateEd25519Key()
	require.NoError(t, err)

	eddsaSigner, err := jwtx.NewSignerEdDSA("eddsa-key", pemKey)
	require.NoError(t, err)

	// Sign a token with EdDSA using helper function
	now := time.Now().UTC()
	claims := jwtx.NewAccessClaims(
		"user-eddsa", "session-eddsa", nil, nil,
		1*time.Minute, exampleIssuer, nil, "", "", now,
	)
	token, err := eddsaSigner.Sign(claims)
	require.NoError(t, err)

	// Create an ES256 verifier
	es256PemKey, err := cryptox.GenerateES256Key()
	require.NoError(t, err)
	es256Signer, err := jwtx.NewSignerES256("es256-key", es256PemKey)
	require.NoError(t, err)

	keyset := jwtx.NewKeySet()
	require.NoError(t, keyset.AddSigner(es256Signer))

	verifier := jwtx.NewVerifierES256(keyset, exampleIssuer, nil)

	// Should fail because the token is EdDSA, not ES256
	_, err = verifier.Verify(token)
	require.Error(t, err)
}

func TestES256ValidateFailsForInvalidKey(t *testing.T) {
	// Try to create a signer with invalid PEM
	_, err := jwtx.NewSignerES256("test", []byte("not-a-pem-key"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid PEM")
}

func TestES256CommonVerifierAdapter(t *testing.T) {
	// Generate ECDSA P-256 keypair
	pemKey, err := cryptox.GenerateES256Key()
	require.NoError(t, err)

	// Create signer
	signer, err := jwtx.NewSignerES256("test-key", pemKey)
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
	verifier := jwtx.NewCommonES256(keyset, exampleIssuer, nil)

	// Verify token - note this returns Claims by value, not pointer
	parsedClaims, err := verifier.Verify(token)
	require.NoError(t, err)
	require.Equal(t, claims.Issuer, parsedClaims.Issuer)
	require.Equal(t, claims.Subject, parsedClaims.Subject)
	require.ElementsMatch(t, claims.Scopes, parsedClaims.Scopes)
}

func TestES256SignaturesAreDeterministic(t *testing.T) {
	// Note: ECDSA signatures are NOT deterministic by default due to the random k value
	// This test just verifies that we can sign and verify multiple times with the same key
	pemKey, err := cryptox.GenerateES256Key()
	require.NoError(t, err)

	signer, err := jwtx.NewSignerES256("test-key", pemKey)
	require.NoError(t, err)

	now := time.Now().UTC()
	claims := jwtx.NewAccessClaims(
		"user-123", "session-test", nil, nil,
		1*time.Minute, exampleIssuer, nil, "", "", now,
	)

	// Sign multiple times
	token1, err := signer.Sign(claims)
	require.NoError(t, err)

	token2, err := signer.Sign(claims)
	require.NoError(t, err)

	// Signatures will differ due to random k, but both should verify
	keyset := jwtx.NewKeySet()
	require.NoError(t, keyset.AddSigner(signer))
	verifier := jwtx.NewVerifierES256(keyset, exampleIssuer, nil)

	_, err = verifier.Verify(token1)
	require.NoError(t, err)

	_, err = verifier.Verify(token2)
	require.NoError(t, err)
}
