package httpx

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aussiebroadwan/bartab/pkg/slogx"
	"golang.org/x/time/rate"
)

// RateLimitConfig defines the rate limiting parameters.
type RateLimitConfig struct {
	// RequestsPerWindow is the number of requests allowed in the time window
	RequestsPerWindow int
	// Window is the time window for rate limiting
	Window time.Duration
	// Burst allows for temporary bursts above the rate limit
	Burst int
}

// Common rate limit profiles for different endpoint types
// These can be overridden via environment variables (see init() below)
var (
	// StrictLimit for authentication endpoints (brute force prevention)
	// Allows 5 requests per minute, with all 5 available as a burst
	// Override with: RATELIMIT_STRICT_REQUESTS, RATELIMIT_STRICT_WINDOW_SEC, RATELIMIT_STRICT_BURST
	StrictLimit = RateLimitConfig{
		RequestsPerWindow: 5,
		Window:            time.Minute,
		Burst:             5,
	}

	// ModerateLimit for authenticated operations
	// Allows 20 requests per minute, with all 20 available as a burst
	// Override with: RATELIMIT_MODERATE_REQUESTS, RATELIMIT_MODERATE_WINDOW_SEC, RATELIMIT_MODERATE_BURST
	ModerateLimit = RateLimitConfig{
		RequestsPerWindow: 20,
		Window:            time.Minute,
		Burst:             20,
	}

	// LenientLimit for less sensitive operations
	// Allows 100 requests per minute, with all 100 available as a burst
	// Override with: RATELIMIT_LENIENT_REQUESTS, RATELIMIT_LENIENT_WINDOW_SEC, RATELIMIT_LENIENT_BURST
	LenientLimit = RateLimitConfig{
		RequestsPerWindow: 100,
		Window:            time.Minute,
		Burst:             100,
	}

	// PublicLimit for public read-only endpoints
	// Allows 1000 requests per minute, with all 1000 available as a burst
	// Override with: RATELIMIT_PUBLIC_REQUESTS, RATELIMIT_PUBLIC_WINDOW_SEC, RATELIMIT_PUBLIC_BURST
	PublicLimit = RateLimitConfig{
		RequestsPerWindow: 1000,
		Window:            time.Minute,
		Burst:             1000,
	}
)

func init() {
	// Allow overriding rate limits via environment variables (useful for testing)
	StrictLimit = ParseRateLimitFromEnv("STRICT", StrictLimit)
	ModerateLimit = ParseRateLimitFromEnv("MODERATE", ModerateLimit)
	LenientLimit = ParseRateLimitFromEnv("LENIENT", LenientLimit)
	PublicLimit = ParseRateLimitFromEnv("PUBLIC", PublicLimit)
}

// ParseRateLimitFromEnv reads rate limit configuration from environment variables.
// Environment variables follow the pattern: RATELIMIT_{prefix}_{field}
// For example: RATELIMIT_STRICT_REQUESTS, RATELIMIT_STRICT_WINDOW_SEC, RATELIMIT_STRICT_BURST
// This function is exported to allow custom rate limit configurations from environment variables.
func ParseRateLimitFromEnv(prefix string, defaultConfig RateLimitConfig) RateLimitConfig {
	config := defaultConfig

	// Parse requests per window
	if val := os.Getenv("RATELIMIT_" + prefix + "_REQUESTS"); val != "" {
		if requests, err := strconv.Atoi(val); err == nil && requests > 0 {
			config.RequestsPerWindow = requests
		}
	}

	// Parse window duration in seconds
	if val := os.Getenv("RATELIMIT_" + prefix + "_WINDOW_SEC"); val != "" {
		if windowSec, err := strconv.Atoi(val); err == nil && windowSec > 0 {
			config.Window = time.Duration(windowSec) * time.Second
		}
	}

	// Parse burst size
	if val := os.Getenv("RATELIMIT_" + prefix + "_BURST"); val != "" {
		if burst, err := strconv.Atoi(val); err == nil && burst > 0 {
			config.Burst = burst
		}
	}

	return config
}

// KeyExtractor is a function that extracts a unique key from the request
// for rate limiting purposes (e.g., IP address, user ID, client ID, etc.)
type KeyExtractor func(*http.Request) string

// Common key extractors

// IPKeyExtractor extracts the client IP address from the request.
// It handles X-Forwarded-For and X-Real-IP headers for proxied requests.
func IPKeyExtractor(r *http.Request) string {
	// Check X-Forwarded-For header (comma-separated list)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}

	// Fallback to RemoteAddr
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

// UserIDKeyExtractor extracts the user ID from the request context.
// Returns empty string if no user ID is found.
func UserIDKeyExtractor(r *http.Request) string {
	if userID, ok := r.Context().Value(CtxKeyUserID).(string); ok {
		return userID
	}
	return ""
}

// CompositeKeyExtractor combines multiple key extractors with a separator.
// Example: CompositeKeyExtractor(":", IPKeyExtractor, UserIDKeyExtractor)
// would produce keys like "192.168.1.1:user123"
func CompositeKeyExtractor(sep string, extractors ...KeyExtractor) KeyExtractor {
	return func(r *http.Request) string {
		var parts []string
		for _, extractor := range extractors {
			if key := extractor(r); key != "" {
				parts = append(parts, key)
			}
		}
		return strings.Join(parts, sep)
	}
}

// FormFieldKeyExtractor extracts a key from a form field (works for both GET and POST).
// Use this for extracting username, client_id, etc. from request parameters.
func FormFieldKeyExtractor(fieldName string) KeyExtractor {
	return func(r *http.Request) string {
		// Try to parse form (handles both URL params and POST body)
		if err := r.ParseForm(); err == nil {
			return r.FormValue(fieldName)
		}
		return ""
	}
}

// rateLimiter manages rate limiters for different keys
type rateLimiter struct {
	limiters sync.Map // map[string]*rate.Limiter
	rate     rate.Limit
	burst    int
	mu       sync.Mutex
	// Cleanup old limiters periodically
	lastCleanup time.Time
}

// getLimiter retrieves or creates a rate limiter for the given key
func (rl *rateLimiter) getLimiter(key string) *rate.Limiter {
	// Fast path: limiter already exists
	if limiter, ok := rl.limiters.Load(key); ok {
		return limiter.(*rate.Limiter)
	}

	// Slow path: create new limiter
	limiter := rate.NewLimiter(rl.rate, rl.burst)
	actual, _ := rl.limiters.LoadOrStore(key, limiter)

	// Periodic cleanup to prevent memory leak
	rl.maybeCleanup()

	return actual.(*rate.Limiter)
}

// maybeCleanup removes old limiters that haven't been used recently
// This prevents memory leaks from accumulating limiters for ephemeral keys
func (rl *rateLimiter) maybeCleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Only cleanup once every 5 minutes
	if time.Since(rl.lastCleanup) < 5*time.Minute {
		return
	}

	rl.lastCleanup = time.Now()

	// Remove limiters that have full token buckets (haven't been used recently)
	// This is a heuristic - if a limiter has all its tokens, it's likely inactive
	rl.limiters.Range(func(key, value any) bool {
		limiter := value.(*rate.Limiter)
		// If the limiter would allow burst requests, it's been idle
		if limiter.Tokens() >= float64(rl.burst) {
			rl.limiters.Delete(key)
		}
		return true
	})
}

// RateLimitMiddleware creates a rate limiting middleware with the given configuration.
// The keyExtractor determines how requests are grouped for rate limiting.
func RateLimitMiddleware(config RateLimitConfig, keyExtractor KeyExtractor) Middleware {
	// Calculate rate per second from requests per window
	ratePerSecond := float64(config.RequestsPerWindow) / config.Window.Seconds()

	rl := &rateLimiter{
		rate:        rate.Limit(ratePerSecond),
		burst:       config.Burst,
		lastCleanup: time.Now(),
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			log := slogx.FromContext(ctx)

			// Extract the key for this request
			key := keyExtractor(r)
			if key == "" {
				// If we can't extract a key, allow the request but log it
				log.Warn("rate limit: unable to extract key, allowing request")
				next.ServeHTTP(w, r)
				return
			}

			// Get or create the limiter for this key
			limiter := rl.getLimiter(key)

			// Check if the request is allowed
			if !limiter.Allow() {
				// Calculate retry-after (when the next token will be available)
				reservation := limiter.Reserve()
				delay := reservation.Delay()
				reservation.Cancel() // Don't actually consume the reservation

				retryAfter := max(int(delay.Seconds()), 1)

				w.Header().Set("Retry-After", fmt.Sprintf("%d", retryAfter))
				w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%d", config.RequestsPerWindow))
				w.Header().Set("X-RateLimit-Window", config.Window.String())

				log.Warn("rate limit exceeded",
					"key", key,
					"endpoint", r.URL.Path,
					"retry_after", retryAfter,
				)

				WriteJSON(w, http.StatusTooManyRequests, map[string]string{
					"error":             "rate_limit_exceeded",
					"error_description": "Too many requests. Please try again later.",
				})
				return
			}

			// Request is allowed, continue to next handler
			next.ServeHTTP(w, r)
		})
	}
}

// Convenience functions for common rate limiting scenarios

// RateLimitByIP creates a rate limiter that limits by IP address only.
func RateLimitByIP(config RateLimitConfig) Middleware {
	return RateLimitMiddleware(config, IPKeyExtractor)
}

// RateLimitByUser creates a rate limiter that limits by authenticated user ID.
// Falls back to IP if no user is authenticated.
func RateLimitByUser(config RateLimitConfig) Middleware {
	return RateLimitMiddleware(config, CompositeKeyExtractor(":",
		UserIDKeyExtractor,
		IPKeyExtractor,
	))
}

// RateLimitByIPAndFormField creates a rate limiter that limits by IP + form field.
// Useful for limiting login attempts by IP + username.
func RateLimitByIPAndFormField(config RateLimitConfig, fieldName string) Middleware {
	return RateLimitMiddleware(config, CompositeKeyExtractor(":",
		IPKeyExtractor,
		FormFieldKeyExtractor(fieldName),
	))
}
