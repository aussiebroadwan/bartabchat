package jwtx

import (
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

// EdDSAVerifier validates JWTs signed using EdDSA (Ed25519).
type EdDSAVerifier struct {
	keys   *KeySet
	issuer string
	aud    []string
}

// NewVerifierEdDSA creates a verifier using a KeySet of Ed25519 public keys.
func NewVerifierEdDSA(keys *KeySet, issuer string, aud []string) *EdDSAVerifier {
	return &EdDSAVerifier{keys: keys, issuer: issuer, aud: aud}
}

// Verify validates the JWT string and returns its parsed Claims.
func (v *EdDSAVerifier) Verify(tokenStr string) (*Claims, error) {
	parser := jwt.NewParser(jwt.WithValidMethods([]string{jwt.SigningMethodEdDSA.Alg()}))

	token, err := parser.ParseWithClaims(tokenStr, &Claims{}, func(t *jwt.Token) (any, error) {
		// Need the kid to know which key to use
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, errors.New("jwtx: missing kid")
		}

		// Try to find this key in our set
		pub, err := v.keys.Get(kid)
		if err != nil {
			return nil, fmt.Errorf("jwtx: unknown kid %q: %w", kid, err)
		}

		// Make sure it's actually an Ed25519 key
		ed25519Pub, ok := pub.(ed25519.PublicKey)
		if !ok {
			return nil, errors.New("jwtx: invalid Ed25519 key type")
		}
		return ed25519Pub, nil
	})
	if err != nil {
		return nil, fmt.Errorf("jwtx: parse or verify: %w", err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, errors.New("jwtx: invalid token claims")
	}

	// Now check all the claim requirements
	if err := claims.ValidateIssuer(v.issuer); err != nil {
		return nil, err
	}
	if err := claims.ValidateAudience(v.aud); err != nil {
		return nil, err
	}
	if err := claims.ValidateExpiry(); err != nil {
		return nil, err
	}

	return claims, nil
}
