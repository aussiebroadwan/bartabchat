package slogx

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/aussiebroadwan/bartab/pkg/idx"
)

// HTTPMiddleware logs requests and attaches a contextual logger into request context.
func HTTPMiddleware(base *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rw := &responseWriter{ResponseWriter: w, status: http.StatusOK}

			// Generate a request ID if not provided via X-Request-ID header
			reqID := r.Header.Get("X-Request-ID")
			if reqID == "" {
				reqID = idx.New().String()
			}

			// Create contextual logger
			logger := base.With(
				"req_id", reqID,
				"method", r.Method,
				"path", r.URL.Path,
				"remote_addr", r.RemoteAddr,
			)

			// Attach to context for downstream use
			ctx := WithContext(r.Context(), logger)
			r = r.WithContext(ctx)

			// Serve request
			next.ServeHTTP(rw, r)

			duration := time.Since(start).Milliseconds()
			logger.Info("http_request",
				"status", rw.status,
				"duration_ms", duration,
				"user_agent", r.UserAgent(),
			)
		})
	}
}

type responseWriter struct {
	http.ResponseWriter

	status int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}
