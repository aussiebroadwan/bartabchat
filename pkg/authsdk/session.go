package authsdk

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Session represents an authenticated session with automatic token refresh.
// All Session methods automatically handle token expiration and refresh when needed.
type Session struct {
	client *SDKClient

	mu           sync.RWMutex
	accessToken  string
	refreshToken string
	clientID     string
	expiresAt    time.Time
	scopes       map[string]bool // Granted scopes for fast lookup
}

// Revoke revokes the current refresh token, invalidating this session.
func (s *Session) Revoke(ctx context.Context) error {
	s.mu.RLock()
	refreshToken := s.refreshToken
	clientID := s.clientID
	s.mu.RUnlock()

	if refreshToken == "" {
		return fmt.Errorf("no refresh token to revoke")
	}

	return s.client.RevokeToken(ctx, clientID, refreshToken)
}

// newSession creates a new authenticated session from a token response.
func newSession(client *SDKClient, clientID string, tokenResp *TokenResponse) *Session {
	expiresAt := time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)

	// Subtract 30 seconds buffer to refresh before actual expiry
	expiresAt = expiresAt.Add(-30 * time.Second)

	// Parse scopes into a map for fast lookup
	scopes := parseScopes(tokenResp.Scope)

	return &Session{
		client:       client,
		clientID:     clientID,
		accessToken:  tokenResp.AccessToken,
		refreshToken: tokenResp.RefreshToken,
		expiresAt:    expiresAt,
		scopes:       scopes,
	}
}

// parseScopes parses a space-delimited scope string into a map for fast lookup.
func parseScopes(scopeStr string) map[string]bool {
	if scopeStr == "" {
		return make(map[string]bool)
	}

	parts := strings.Fields(scopeStr)
	scopes := make(map[string]bool, len(parts))
	for _, scope := range parts {
		scopes[scope] = true
	}
	return scopes
}

// getValidToken returns a valid access token, automatically refreshing if expired.
func (s *Session) getValidToken(ctx context.Context) (string, error) {
	s.mu.RLock()
	if time.Now().Before(s.expiresAt) {
		token := s.accessToken
		s.mu.RUnlock()
		return token, nil
	}
	s.mu.RUnlock()

	// Token expired, need to refresh
	s.mu.Lock()
	defer s.mu.Unlock()

	// Double-check after acquiring write lock (another goroutine may have refreshed)
	if time.Now().Before(s.expiresAt) {
		return s.accessToken, nil
	}

	// Check if we have a refresh token
	if s.refreshToken == "" {
		return "", fmt.Errorf("access token expired and no refresh token available")
	}

	// Perform refresh
	tokenResp, err := s.client.RefreshGrant(ctx, s.clientID, s.refreshToken)
	if err != nil {
		return "", fmt.Errorf("failed to refresh token: %w", err)
	}

	// Update stored tokens and scopes
	s.accessToken = tokenResp.AccessToken
	s.refreshToken = tokenResp.RefreshToken
	s.expiresAt = time.Now().Add(time.Duration(tokenResp.ExpiresIn)*time.Second - 30*time.Second)
	s.scopes = parseScopes(tokenResp.Scope)

	return s.accessToken, nil
}

// AccessToken returns the current access token without checking expiration.
// For most use cases, prefer using the Session methods which handle refresh automatically.
func (s *Session) AccessToken() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.accessToken
}

// RefreshToken returns the current refresh token.
// For most use cases, prefer using the Session methods which handle refresh automatically.
func (s *Session) RefreshToken() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.refreshToken
}

// Scopes returns a copy of the current granted scopes as a slice.
func (s *Session) Scopes() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	scopes := make([]string, 0, len(s.scopes))
	for scope := range s.scopes {
		scopes = append(scopes, scope)
	}
	return scopes
}

// HasScope returns true if the session has the specified scope.
func (s *Session) HasScope(scope string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.scopes[scope]
}

// HasAllScopes returns true if the session has all of the specified scopes.
func (s *Session) HasAllScopes(scopes ...string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, scope := range scopes {
		if !s.scopes[scope] {
			return false
		}
	}
	return true
}

// HasAnyScope returns true if the session has at least one of the specified scopes.
func (s *Session) HasAnyScope(scopes ...string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, scope := range scopes {
		if s.scopes[scope] {
			return true
		}
	}
	return false
}

// checkScopes checks if the session has all required scopes.
// Returns an error if scope checking is enabled and scopes are missing.
func (s *Session) checkScopes(required ...string) error {
	if !s.client.CheckScopes {
		return nil // Scope checking disabled
	}

	if len(required) == 0 {
		return nil // No scopes required
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	var missing []string
	for _, scope := range required {
		if !s.scopes[scope] {
			missing = append(missing, scope)
		}
	}

	if len(missing) > 0 {
		return fmt.Errorf("missing required scope(s): %s", strings.Join(missing, ", "))
	}

	return nil
}
