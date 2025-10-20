package jwtx

import (
	"crypto/rsa"
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

// RS256Verifier validates JWTs signed using RS256.
type RS256Verifier struct {
	keys   *KeySet
	issuer string
	aud    []string
}

// NewVerifierRS256 creates a verifier using a KeySet of RSA public keys.
func NewVerifierRS256(keys *KeySet, issuer string, aud []string) *RS256Verifier {
	return &RS256Verifier{keys: keys, issuer: issuer, aud: aud}
}

// Verify validates the JWT string and returns its parsed Claims.
func (v *RS256Verifier) Verify(tokenStr string) (*Claims, error) {
	parser := jwt.NewParser(jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}))

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

		// Make sure it's actually an RSA key (it should be, watch it not be)
		rsaPub, ok := pub.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("jwtx: invalid RSA key type")
		}
		return rsaPub, nil
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
