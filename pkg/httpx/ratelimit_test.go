package httpx_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aussiebroadwan/bartab/pkg/httpx"
	"github.com/stretchr/testify/require"
)

func TestIPKeyExtractor(t *testing.T) {
	t.Run("extracts from RemoteAddr", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "192.168.1.1:12345"

		ip := httpx.IPKeyExtractor(req)
		require.Equal(t, "192.168.1.1", ip)
	})

	t.Run("prefers X-Forwarded-For", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		req.Header.Set("X-Forwarded-For", "203.0.113.1, 192.168.1.1")

		ip := httpx.IPKeyExtractor(req)
		require.Equal(t, "203.0.113.1", ip)
	})

	t.Run("uses X-Real-IP if X-Forwarded-For absent", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		req.Header.Set("X-Real-IP", "203.0.113.2")

		ip := httpx.IPKeyExtractor(req)
		require.Equal(t, "203.0.113.2", ip)
	})
}

func TestFormFieldKeyExtractor(t *testing.T) {
	t.Run("extracts from GET params", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/?username=alice", nil)

		extractor := httpx.FormFieldKeyExtractor("username")
		username := extractor(req)
		require.Equal(t, "alice", username)
	})

	t.Run("extracts from POST form", func(t *testing.T) {
		form := url.Values{}
		form.Set("username", "bob")

		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		extractor := httpx.FormFieldKeyExtractor("username")
		username := extractor(req)
		require.Equal(t, "bob", username)
	})

	t.Run("returns empty for missing field", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)

		extractor := httpx.FormFieldKeyExtractor("username")
		username := extractor(req)
		require.Equal(t, "", username)
	})
}

func TestCompositeKeyExtractor(t *testing.T) {
	t.Run("combines multiple extractors", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/?username=alice", nil)
		req.RemoteAddr = "192.168.1.1:12345"

		extractor := httpx.CompositeKeyExtractor(":",
			httpx.IPKeyExtractor,
			httpx.FormFieldKeyExtractor("username"),
		)

		key := extractor(req)
		require.Equal(t, "192.168.1.1:alice", key)
	})

	t.Run("skips empty values", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil) // no username param
		req.RemoteAddr = "192.168.1.1:12345"

		extractor := httpx.CompositeKeyExtractor(":",
			httpx.IPKeyExtractor,
			httpx.FormFieldKeyExtractor("username"),
		)

		key := extractor(req)
		require.Equal(t, "192.168.1.1", key)
	})
}

func TestRateLimitMiddleware(t *testing.T) {
	t.Run("allows requests under limit", func(t *testing.T) {
		config := httpx.RateLimitConfig{
			RequestsPerWindow: 5,
			Window:            time.Second,
			Burst:             5, // Allow all 5 requests as a burst
		}

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware := httpx.RateLimitMiddleware(config, httpx.IPKeyExtractor)
		limitedHandler := middleware(handler)

		// Make 5 requests - all should succeed
		for i := range 5 {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = "192.168.1.1:12345"
			rec := httptest.NewRecorder()

			limitedHandler.ServeHTTP(rec, req)
			require.Equal(t, http.StatusOK, rec.Code, "request %d should succeed", i+1)
		}
	})

	t.Run("blocks requests over limit", func(t *testing.T) {
		config := httpx.RateLimitConfig{
			RequestsPerWindow: 3,
			Window:            time.Minute,
			Burst:             3,
		}

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware := httpx.RateLimitMiddleware(config, httpx.IPKeyExtractor)
		limitedHandler := middleware(handler)

		// Make 3 requests - should succeed
		for i := range 3 {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = "192.168.1.1:12345"
			rec := httptest.NewRecorder()

			limitedHandler.ServeHTTP(rec, req)
			require.Equal(t, http.StatusOK, rec.Code, "request %d should succeed", i+1)
		}

		// 4th request should be blocked
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		rec := httptest.NewRecorder()

		limitedHandler.ServeHTTP(rec, req)
		require.Equal(t, http.StatusTooManyRequests, rec.Code)
		require.NotEmpty(t, rec.Header().Get("Retry-After"))
	})

	t.Run("different keys are tracked separately", func(t *testing.T) {
		config := httpx.RateLimitConfig{
			RequestsPerWindow: 2,
			Window:            time.Minute,
			Burst:             2,
		}

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware := httpx.RateLimitMiddleware(config, httpx.IPKeyExtractor)
		limitedHandler := middleware(handler)

		// Make 2 requests from IP1 - should succeed
		for range 2 {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = "192.168.1.1:12345"
			rec := httptest.NewRecorder()

			limitedHandler.ServeHTTP(rec, req)
			require.Equal(t, http.StatusOK, rec.Code)
		}

		// 3rd request from IP1 should be blocked
		req1 := httptest.NewRequest(http.MethodGet, "/", nil)
		req1.RemoteAddr = "192.168.1.1:12345"
		rec1 := httptest.NewRecorder()
		limitedHandler.ServeHTTP(rec1, req1)
		require.Equal(t, http.StatusTooManyRequests, rec1.Code)

		// But IP2 should still be allowed
		req2 := httptest.NewRequest(http.MethodGet, "/", nil)
		req2.RemoteAddr = "192.168.1.2:12345"
		rec2 := httptest.NewRecorder()
		limitedHandler.ServeHTTP(rec2, req2)
		require.Equal(t, http.StatusOK, rec2.Code)
	})

	t.Run("burst allows temporary spikes", func(t *testing.T) {
		config := httpx.RateLimitConfig{
			RequestsPerWindow: 10, // 10 per second
			Window:            time.Second,
			Burst:             5, // but allow 5 at once
		}

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware := httpx.RateLimitMiddleware(config, httpx.IPKeyExtractor)
		limitedHandler := middleware(handler)

		// Should be able to make 5 requests immediately (burst)
		for i := range 5 {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = "192.168.1.1:12345"
			rec := httptest.NewRecorder()

			limitedHandler.ServeHTTP(rec, req)
			require.Equal(t, http.StatusOK, rec.Code, "burst request %d should succeed", i+1)
		}
	})

	t.Run("allows request when key extractor returns empty", func(t *testing.T) {
		config := httpx.RateLimitConfig{
			RequestsPerWindow: 1,
			Window:            time.Minute,
			Burst:             1,
		}

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		// Extractor that always returns empty
		emptyExtractor := func(r *http.Request) string {
			return ""
		}

		middleware := httpx.RateLimitMiddleware(config, emptyExtractor)
		limitedHandler := middleware(handler)

		// Multiple requests should all succeed even though limit is 1
		for range 3 {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			rec := httptest.NewRecorder()

			limitedHandler.ServeHTTP(rec, req)
			require.Equal(t, http.StatusOK, rec.Code)
		}
	})
}

func TestRateLimitByIP(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	config := httpx.RateLimitConfig{
		RequestsPerWindow: 2,
		Window:            time.Minute,
		Burst:             2,
	}

	middleware := httpx.RateLimitByIP(config)
	limitedHandler := middleware(handler)

	// Make 2 requests - should succeed
	for range 2 {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		rec := httptest.NewRecorder()

		limitedHandler.ServeHTTP(rec, req)
		require.Equal(t, http.StatusOK, rec.Code)
	}

	// 3rd request should be blocked
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	rec := httptest.NewRecorder()

	limitedHandler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusTooManyRequests, rec.Code)
}

func TestRateLimitByIPAndFormField(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	config := httpx.RateLimitConfig{
		RequestsPerWindow: 2,
		Window:            time.Minute,
		Burst:             2,
	}

	middleware := httpx.RateLimitByIPAndFormField(config, "username")
	limitedHandler := middleware(handler)

	// Make 2 requests with same IP + username - should succeed
	for range 2 {
		req := httptest.NewRequest(http.MethodGet, "/?username=alice", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		rec := httptest.NewRecorder()

		limitedHandler.ServeHTTP(rec, req)
		require.Equal(t, http.StatusOK, rec.Code)
	}

	// 3rd request with same IP + username should be blocked
	req1 := httptest.NewRequest(http.MethodGet, "/?username=alice", nil)
	req1.RemoteAddr = "192.168.1.1:12345"
	rec1 := httptest.NewRecorder()
	limitedHandler.ServeHTTP(rec1, req1)
	require.Equal(t, http.StatusTooManyRequests, rec1.Code)

	// But same IP with different username should be allowed
	req2 := httptest.NewRequest(http.MethodGet, "/?username=bob", nil)
	req2.RemoteAddr = "192.168.1.1:12345"
	rec2 := httptest.NewRecorder()
	limitedHandler.ServeHTTP(rec2, req2)
	require.Equal(t, http.StatusOK, rec2.Code)
}

func TestRateLimitProfiles(t *testing.T) {
	profiles := map[string]httpx.RateLimitConfig{
		"strict":   httpx.StrictLimit,
		"moderate": httpx.ModerateLimit,
		"lenient":  httpx.LenientLimit,
		"public":   httpx.PublicLimit,
	}

	for name, config := range profiles {
		t.Run(name, func(t *testing.T) {
			require.Greater(t, config.RequestsPerWindow, 0, "requests per window must be positive")
			require.Greater(t, config.Window, time.Duration(0), "window must be positive")
			require.Greater(t, config.Burst, 0, "burst must be positive")
		})
	}

	// Verify ordering: strict < moderate < lenient < public
	require.Less(t, httpx.StrictLimit.RequestsPerWindow, httpx.ModerateLimit.RequestsPerWindow)
	require.Less(t, httpx.ModerateLimit.RequestsPerWindow, httpx.LenientLimit.RequestsPerWindow)
	require.Less(t, httpx.LenientLimit.RequestsPerWindow, httpx.PublicLimit.RequestsPerWindow)
}

func TestRateLimitHeaders(t *testing.T) {
	config := httpx.RateLimitConfig{
		RequestsPerWindow: 1,
		Window:            time.Minute,
		Burst:             1, // This one is correct - we want to test hitting the limit after 1 request
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware := httpx.RateLimitMiddleware(config, httpx.IPKeyExtractor)
	limitedHandler := middleware(handler)

	// First request succeeds
	req1 := httptest.NewRequest(http.MethodGet, "/", nil)
	req1.RemoteAddr = "192.168.1.1:12345"
	rec1 := httptest.NewRecorder()
	limitedHandler.ServeHTTP(rec1, req1)
	require.Equal(t, http.StatusOK, rec1.Code)

	// Second request should be rate limited with headers
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.RemoteAddr = "192.168.1.1:12345"
	rec2 := httptest.NewRecorder()
	limitedHandler.ServeHTTP(rec2, req2)

	require.Equal(t, http.StatusTooManyRequests, rec2.Code)
	require.NotEmpty(t, rec2.Header().Get("Retry-After"), "should include Retry-After header")
	require.Equal(t, "1", rec2.Header().Get("X-RateLimit-Limit"))
	require.Equal(t, "1m0s", rec2.Header().Get("X-RateLimit-Window"))

	// Verify response body is JSON
	body := rec2.Body.String()
	require.Contains(t, body, "rate_limit_exceeded")
	require.Contains(t, body, "error_description")
}

// Benchmark rate limiting overhead
func BenchmarkRateLimitMiddleware(b *testing.B) {
	config := httpx.RateLimitConfig{
		RequestsPerWindow: 1000000, // High limit so we don't hit it
		Window:            time.Minute,
		Burst:             1000,
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware := httpx.RateLimitMiddleware(config, httpx.IPKeyExtractor)
	limitedHandler := middleware(handler)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.168.1.1:12345"

	for b.Loop() {
		rec := httptest.NewRecorder()
		limitedHandler.ServeHTTP(rec, req)
	}
}

// Benchmark with many different IPs (tests sync.Map performance)
func BenchmarkRateLimitManyIPs(b *testing.B) {
	config := httpx.RateLimitConfig{
		RequestsPerWindow: 1000000,
		Window:            time.Minute,
		Burst:             1000,
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware := httpx.RateLimitMiddleware(config, httpx.IPKeyExtractor)
	limitedHandler := middleware(handler)

	for i := 0; b.Loop(); i++ {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = fmt.Sprintf("192.168.%d.%d:12345", i%255, (i/255)%255)
		rec := httptest.NewRecorder()
		limitedHandler.ServeHTTP(rec, req)
	}
}

func TestParseRateLimitFromEnv(t *testing.T) {
	defaultConfig := httpx.RateLimitConfig{
		RequestsPerWindow: 10,
		Window:            time.Minute,
		Burst:             10,
	}

	t.Run("NoEnvVarsUsesDefaults", func(t *testing.T) {
		config := httpx.ParseRateLimitFromEnv("TEST", defaultConfig)
		require.Equal(t, defaultConfig.RequestsPerWindow, config.RequestsPerWindow)
		require.Equal(t, defaultConfig.Window, config.Window)
		require.Equal(t, defaultConfig.Burst, config.Burst)
	})

	t.Run("OverrideRequestsPerWindow", func(t *testing.T) {
		os.Setenv("RATELIMIT_TEST_REQUESTS", "50")
		defer os.Unsetenv("RATELIMIT_TEST_REQUESTS")

		config := httpx.ParseRateLimitFromEnv("TEST", defaultConfig)
		require.Equal(t, 50, config.RequestsPerWindow)
		require.Equal(t, defaultConfig.Window, config.Window)
		require.Equal(t, defaultConfig.Burst, config.Burst)
	})

	t.Run("OverrideWindowDuration", func(t *testing.T) {
		os.Setenv("RATELIMIT_TEST_WINDOW_SEC", "120")
		defer os.Unsetenv("RATELIMIT_TEST_WINDOW_SEC")

		config := httpx.ParseRateLimitFromEnv("TEST", defaultConfig)
		require.Equal(t, defaultConfig.RequestsPerWindow, config.RequestsPerWindow)
		require.Equal(t, 120*time.Second, config.Window)
		require.Equal(t, defaultConfig.Burst, config.Burst)
	})

	t.Run("OverrideBurst", func(t *testing.T) {
		os.Setenv("RATELIMIT_TEST_BURST", "100")
		defer os.Unsetenv("RATELIMIT_TEST_BURST")

		config := httpx.ParseRateLimitFromEnv("TEST", defaultConfig)
		require.Equal(t, defaultConfig.RequestsPerWindow, config.RequestsPerWindow)
		require.Equal(t, defaultConfig.Window, config.Window)
		require.Equal(t, 100, config.Burst)
	})

	t.Run("OverrideAllParameters", func(t *testing.T) {
		os.Setenv("RATELIMIT_TEST_REQUESTS", "200")
		os.Setenv("RATELIMIT_TEST_WINDOW_SEC", "30")
		os.Setenv("RATELIMIT_TEST_BURST", "250")
		defer func() {
			os.Unsetenv("RATELIMIT_TEST_REQUESTS")
			os.Unsetenv("RATELIMIT_TEST_WINDOW_SEC")
			os.Unsetenv("RATELIMIT_TEST_BURST")
		}()

		config := httpx.ParseRateLimitFromEnv("TEST", defaultConfig)
		require.Equal(t, 200, config.RequestsPerWindow)
		require.Equal(t, 30*time.Second, config.Window)
		require.Equal(t, 250, config.Burst)
	})

	t.Run("InvalidValuesUseDefaults", func(t *testing.T) {
		os.Setenv("RATELIMIT_TEST_REQUESTS", "invalid")
		os.Setenv("RATELIMIT_TEST_WINDOW_SEC", "-10")
		os.Setenv("RATELIMIT_TEST_BURST", "not-a-number")
		defer func() {
			os.Unsetenv("RATELIMIT_TEST_REQUESTS")
			os.Unsetenv("RATELIMIT_TEST_WINDOW_SEC")
			os.Unsetenv("RATELIMIT_TEST_BURST")
		}()

		config := httpx.ParseRateLimitFromEnv("TEST", defaultConfig)
		require.Equal(t, defaultConfig.RequestsPerWindow, config.RequestsPerWindow)
		require.Equal(t, defaultConfig.Window, config.Window)
		require.Equal(t, defaultConfig.Burst, config.Burst)
	})

	t.Run("ZeroValuesUseDefaults", func(t *testing.T) {
		os.Setenv("RATELIMIT_TEST_REQUESTS", "0")
		os.Setenv("RATELIMIT_TEST_WINDOW_SEC", "0")
		os.Setenv("RATELIMIT_TEST_BURST", "0")
		defer func() {
			os.Unsetenv("RATELIMIT_TEST_REQUESTS")
			os.Unsetenv("RATELIMIT_TEST_WINDOW_SEC")
			os.Unsetenv("RATELIMIT_TEST_BURST")
		}()

		config := httpx.ParseRateLimitFromEnv("TEST", defaultConfig)
		require.Equal(t, defaultConfig.RequestsPerWindow, config.RequestsPerWindow)
		require.Equal(t, defaultConfig.Window, config.Window)
		require.Equal(t, defaultConfig.Burst, config.Burst)
	})
}
