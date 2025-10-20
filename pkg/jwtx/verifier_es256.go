package jwtx

import (
	"crypto/ecdsa"
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

// ES256Verifier validates JWTs signed using ES256 (ECDSA P-256 with SHA-256).
type ES256Verifier struct {
	keys   *KeySet
	issuer string
	aud    []string
}

// NewVerifierES256 creates a verifier using a KeySet of ECDSA P-256 public keys.
func NewVerifierES256(keys *KeySet, issuer string, aud []string) *ES256Verifier {
	return &ES256Verifier{keys: keys, issuer: issuer, aud: aud}
}

// Verify validates the JWT string and returns its parsed Claims.
func (v *ES256Verifier) Verify(tokenStr string) (*Claims, error) {
	parser := jwt.NewParser(jwt.WithValidMethods([]string{jwt.SigningMethodES256.Alg()}))

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

		// Make sure it's actually an ECDSA key
		ecdsaPub, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return nil, errors.New("jwtx: invalid ECDSA key type")
		}
		return ecdsaPub, nil
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
