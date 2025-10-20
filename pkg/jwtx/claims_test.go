package jwtx_test

import (
	"testing"
	"time"

	"github.com/aussiebroadwan/bartab/pkg/jwtx"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

func TestValidateIssuer(t *testing.T) {
	c := &jwtx.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer: "auth-service",
		},
	}

	t.Run("matching issuer", func(t *testing.T) {
		require.NoError(t, c.ValidateIssuer("auth-service"))
	})

	t.Run("empty expected issuer", func(t *testing.T) {
		require.NoError(t, c.ValidateIssuer(""))
	})

	t.Run("mismatched issuer", func(t *testing.T) {
		err := c.ValidateIssuer("chat-service")
		require.ErrorIs(t, err, jwtx.ErrIssuer)
	})
}

func TestValidateAudience(t *testing.T) {
	c := &jwtx.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Audience: []string{"chat", "media"},
		},
	}

	t.Run("contains match", func(t *testing.T) {
		require.NoError(t, c.ValidateAudience([]string{"chat"}))
	})

	t.Run("multiple match", func(t *testing.T) {
		require.NoError(t, c.ValidateAudience([]string{"foo", "media"}))
	})

	t.Run("no match", func(t *testing.T) {
		err := c.ValidateAudience([]string{"admin"})
		require.ErrorIs(t, err, jwtx.ErrAudience)
	})

	t.Run("empty expected list", func(t *testing.T) {
		require.NoError(t, c.ValidateAudience(nil))
	})
}

func TestValidateExpiry(t *testing.T) {
	now := time.Now().UTC()

	t.Run("valid token", func(t *testing.T) {
		claims := &jwtx.Claims{
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(now.Add(1 * time.Minute)),
			},
		}
		require.NoError(t, claims.ValidateExpiry())
	})

	t.Run("expired token", func(t *testing.T) {
		claims := &jwtx.Claims{
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(now.Add(-1 * time.Minute)),
			},
		}
		require.ErrorIs(t, claims.ValidateExpiry(), jwtx.ErrExpired)
	})

	t.Run("not yet valid", func(t *testing.T) {
		claims := &jwtx.Claims{
			RegisteredClaims: jwt.RegisteredClaims{
				NotBefore: jwt.NewNumericDate(now.Add(1 * time.Minute)),
			},
		}
		require.ErrorIs(t, claims.ValidateExpiry(), jwtx.ErrNotYetValid)
	})

	t.Run("no exp or nbf", func(t *testing.T) {
		claims := &jwtx.Claims{}
		require.NoError(t, claims.ValidateExpiry())
	})
}

func TestValidateExpiryWithLeeway(t *testing.T) {
	now := time.Now().UTC()

	t.Run("valid with leeway", func(t *testing.T) {
		claims := &jwtx.Claims{
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(now.Add(-10 * time.Second)),
			},
		}
		require.NoError(t, claims.ValidateExpiryWithLeeway(30*time.Second))
	})

	t.Run("expired beyond leeway", func(t *testing.T) {
		claims := &jwtx.Claims{
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(now.Add(-2 * time.Minute)),
			},
		}
		require.ErrorIs(t, claims.ValidateExpiryWithLeeway(30*time.Second), jwtx.ErrExpired)
	})
}
