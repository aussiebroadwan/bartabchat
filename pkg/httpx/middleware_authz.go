package httpx

import (
	"net/http"
	"strings"
)

// RequireAnyScope the caller must have at least one of the provided scopes.
func RequireAnyScope(required ...string) func(http.Handler) http.Handler {
	want := make(map[string]struct{}, len(required))
	for _, s := range required {
		want[s] = struct{}{}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			have := scopesFromCtx(r.Context())

			// 1. Ensure at least one required scope is present.
			for _, s := range have {
				if _, ok := want[s]; ok {
					next.ServeHTTP(w, r)
					return
				}
			}

			writeBearerScopeError(w, http.StatusForbidden, required...)
		})
	}
}

// RequireAllScopes the caller must have every scope listed.
func RequireAllScopes(required ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// 1. Build set of scopes the caller has.
			have := make(map[string]struct{})
			for _, s := range scopesFromCtx(r.Context()) {
				have[s] = struct{}{}
			}

			// 2. Ensure every required scope is present.
			for _, req := range required {
				if _, ok := have[req]; !ok {
					writeBearerScopeError(w, http.StatusForbidden, required...)
					return
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RFC 6750-compliant error response for bearer insufficient_scope.
func writeBearerScopeError(w http.ResponseWriter, code int, required ...string) {
	w.Header().
		Set("WWW-Authenticate", `Bearer error="insufficient_scope", scope="`+strings.Join(required, " ")+`"`)
	w.WriteHeader(code)
	_, _ = w.Write([]byte("insufficient_scope"))
}
