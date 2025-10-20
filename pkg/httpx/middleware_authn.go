package httpx

import (
	"context"
	"net/http"
	"strings"

	"github.com/aussiebroadwan/bartab/pkg/jwtx"
	"github.com/aussiebroadwan/bartab/pkg/slogx"
)

func AuthnMiddleware(v jwtx.Verifier) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			log := slogx.FromContext(ctx)

			authz := r.Header.Get("Authorization")
			if authz == "" || !strings.HasPrefix(authz, "Bearer ") {
				writeBearerError(w, "missing bearer token")
				return
			}
			raw := strings.TrimSpace(strings.TrimPrefix(authz, "Bearer"))

			claims, err := v.Verify(raw)
			if err != nil {
				writeBearerError(w, "token verification failed")
				log.Warn("jwt verify failed", "err", err)
				return
			}

			if err := claims.ValidateExpiry(); err != nil {
				writeBearerError(w, "token expired")
				return
			}

			// Inject into context for downstream handlers.
			ctx = contextWithAuth(ctx, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func contextWithAuth(ctx context.Context, c jwtx.Claims) context.Context {
	ctx = context.WithValue(ctx, CtxKeyUserID, c.Subject)
	ctx = context.WithValue(ctx, CtxKeyScopes, c.Scopes)
	ctx = context.WithValue(ctx, CtxKeyClaims, c)
	return ctx
}

// RFC 6750-compliant error response for bearer auth.
func writeBearerError(w http.ResponseWriter, desc string) {
	w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", error_description="`+desc+`"`)
	w.WriteHeader(http.StatusUnauthorized)
}
