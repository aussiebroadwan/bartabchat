package jwtx_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/aussiebroadwan/bartab/pkg/jwtx"
	"github.com/stretchr/testify/require"
)

const exampleIssuer = "auth-service"

func TestRS256SignAndVerify(t *testing.T) {

	// Generate RSA keypair
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privKey),
	})

	kid := "test-key"

	// Create signer
	signer, err := jwtx.NewSignerRS256(kid, privPEM)
	require.NoError(t, err)
	require.NotNil(t, signer)
	require.NoError(t, signer.Validate())

	// Build claims using helper function
	now := time.Now().UTC()
	claims := jwtx.NewAccessClaims(
		"user-123",                          // subject
		"session-abc",                       // session ID
		[]string{"chat:read", "chat:write"}, // scopes
		[]string{"pwd"},                     // AMR
		2*time.Minute,                       // TTL
		exampleIssuer,                       // issuer
		[]string{"chat"},                    // audience
		"testuser",                          // username
		"Test User",                         // preferred name
		now,                                 // issued at time
	)

	// Sign token
	token, err := signer.Sign(claims)
	require.NoError(t, err)
	require.NotEmpty(t, token)

	// Build KeySet for verification
	keyset := jwtx.NewKeySet()
	require.NoError(t, keyset.AddSigner(signer))

	// Create verifier
	verifier := jwtx.NewVerifierRS256(keyset, exampleIssuer, []string{"chat"})

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

func TestRS256VerifyFailsForWrongIssuer(t *testing.T) {
	// Generate RSA keypair
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privKey),
	})

	// Create signer
	signer, err := jwtx.NewSignerRS256("k1", privPEM)
	require.NoError(t, err)

	// Build claims using helper function
	now := time.Now().UTC()
	claims := jwtx.NewAccessClaims(
		"user-123",
		"session-xyz",
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
	verifier := jwtx.NewVerifierRS256(keyset, "wrong-issuer", []string{"chat"})

	// Verify token
	_, err = verifier.Verify(token)
	require.ErrorIs(t, err, jwtx.ErrIssuer)
}

func TestRS256VerifyFailsForUnknownKey(t *testing.T) {
	// Generate two RSA keypairs
	privKey1, _ := rsa.GenerateKey(rand.Reader, 2048)
	privPEM1 := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privKey1),
	})
	signer1, _ := jwtx.NewSignerRS256("key1", privPEM1)

	privKey2, _ := rsa.GenerateKey(rand.Reader, 2048)
	privPEM2 := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privKey2),
	})
	signer2, _ := jwtx.NewSignerRS256("key2", privPEM2)

	// Token signed with key1 using helper function
	now := time.Now().UTC()
	claims := jwtx.NewAccessClaims(
		"user-123", "session-def", nil, nil,
		1*time.Minute, exampleIssuer, nil, "", "", now,
	)
	token, _ := signer1.Sign(claims)

	// Keyset only contains key2
	keyset := jwtx.NewKeySet()
	require.NoError(t, keyset.AddSigner(signer2))

	verifier := jwtx.NewVerifierRS256(keyset, exampleIssuer, nil)

	_, err := verifier.Verify(token)
	require.ErrorIs(t, err, jwtx.ErrNoKey)
}
