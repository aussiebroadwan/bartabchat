package jwtx

import (
	"errors"
	"time"
)

// Verifier validates a JWT and gives you back the claims if it's legit.
type Verifier interface {
	Verify(token string) (Claims, error)
}

// VerifyOptions captures common expectations used by verifiers.
type VerifyOptions struct {
	// Issuer the token must have (claims.iss). Empty means "don't care".
	Issuer string

	// Audience values the token must contain (claims.aud). Empty means "don't care".
	Audience []string

	// Leeway allows small clock skew when validating exp/nbf/iat.
	// Because time sync is never perfect.
	Leeway time.Duration

	// RequireKID enforces presence of the "kid" header.
	RequireKID bool
}

var (
	ErrMalformed   = errors.New("jwtx: malformed token")
	ErrAlgMismatch = errors.New("jwtx: algorithm mismatch")
	ErrUnknownKID  = errors.New("jwtx: unknown kid")
	ErrInvalidSig  = errors.New("jwtx: invalid signature")

	ErrIssuer       = errors.New("jwtx: issuer mismatch")
	ErrAudience     = errors.New("jwtx: audience mismatch")
	ErrExpired      = errors.New("jwtx: token expired")
	ErrNotYetValid  = errors.New("jwtx: token not yet valid")
	ErrInvalidClaim = errors.New("jwtx: invalid claims")
)

// RS256Adapter a Verifier wrapper for RS256.
type RS256Adapter struct{ *RS256Verifier }

func (a RS256Adapter) Verify(token string) (Claims, error) {
	c, err := a.RS256Verifier.Verify(token)
	if err != nil {
		return Claims{}, err
	}
	return *c, nil
}

// NewCommonRS256 returns a Verifier using the RS256 implementation wrapped
// in the common interface.
func NewCommonRS256(keys *KeySet, issuer string, audience []string) Verifier {
	return RS256Adapter{NewVerifierRS256(keys, issuer, audience)}
}

// EdDSAAdapter a Verifier wrapper for EdDSA.
type EdDSAAdapter struct{ *EdDSAVerifier }

func (a EdDSAAdapter) Verify(token string) (Claims, error) {
	c, err := a.EdDSAVerifier.Verify(token)
	if err != nil {
		return Claims{}, err
	}
	return *c, nil
}

// NewCommonEdDSA returns a Verifier using the EdDSA implementation wrapped
// in the common interface.
func NewCommonEdDSA(keys *KeySet, issuer string, audience []string) Verifier {
	return EdDSAAdapter{NewVerifierEdDSA(keys, issuer, audience)}
}

// ES256Adapter a Verifier wrapper for ES256.
type ES256Adapter struct{ *ES256Verifier }

func (a ES256Adapter) Verify(token string) (Claims, error) {
	c, err := a.ES256Verifier.Verify(token)
	if err != nil {
		return Claims{}, err
	}
	return *c, nil
}

// NewCommonES256 returns a Verifier using the ES256 implementation wrapped
// in the common interface.
func NewCommonES256(keys *KeySet, issuer string, audience []string) Verifier {
	return ES256Adapter{NewVerifierES256(keys, issuer, audience)}
}
