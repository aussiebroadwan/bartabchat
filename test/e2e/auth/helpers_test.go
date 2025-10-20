package auth_test

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/aussiebroadwan/bartab/pkg/authsdk"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

/*
 * Common constants and helper functions for auth service end-to-end tests.
 * This includes container setup, service operations, and assertions.
 */

const (
	testImageName = "bartab-auth-test:latest"

	bootstrapToken     = "test-bootstrap-token-12345"
	adminUsername      = "admin"
	adminPreferredName = "Administrator"
	adminPassword      = "Admin123!"
	clientName         = "test-client"
)

var (
	clientScopes = []string{"profile:read", "profile:write", "admin:read", "admin:write"}
)

// defaultRoleDefinitions returns the standard role definitions used in tests.
func defaultRoleDefinitions() []authsdk.RoleDefinition {
	return []authsdk.RoleDefinition{
		{
			Name:   "admin",
			Scopes: []string{"profile:read", "profile:write", "admin:read", "admin:write"},
		},
		{
			Name:   "user",
			Scopes: []string{"profile:read", "profile:write"},
		},
	}
}

// TestMain manages the test lifecycle, builds the Docker image once before
// all tests and cleans it up after all tests complete.
func TestMain(m *testing.M) {
	// Silence testcontainers logging (container lifecycle logs)

	fmt.Fprintf(os.Stdout, "Building Auth Service Docker image...")

	// Build the Docker image once before all tests
	if err := buildDockerImage(); err != nil {
		fmt.Fprintf(os.Stderr, "\nFailed to build Docker image: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stdout, " done\n")

	// Run all tests
	exitCode := m.Run()

	// Clean up the Docker image after all tests complete
	fmt.Fprintf(os.Stdout, "Cleaning up Auth Service Docker image...")
	cleanupDockerImage()
	fmt.Fprintf(os.Stdout, " done\n")

	os.Exit(exitCode)
}

// buildDockerImage builds the test Docker image if it doesn't exist.
func buildDockerImage() error {
	ctx := context.Background()
	cmd := exec.CommandContext(ctx, "docker", "build",
		"-t", testImageName,
		"-f", "../../../cmd/auth/Dockerfile",
		"../../../")
	cmd.Dir = "." // Ensure we're in the test directory
	cmd.Stdout = os.Stdout
	cmd.Stderr = nil

	return cmd.Run()
}

// cleanupDockerImage removes the test Docker image.
func cleanupDockerImage() {
	ctx := context.Background()
	cmd := exec.CommandContext(ctx, "docker", "rmi", "-f", testImageName)
	_ = cmd.Run() // Ignore errors - image might not exist
}

// setupAuthContainer starts the auth service in a container and returns the base URL.
func setupAuthContainer(t *testing.T) (string, func()) {
	t.Helper()
	ctx := context.Background()

	req := testcontainers.ContainerRequest{
		Image:        testImageName, // I changed this from `FromDockerfile` to `Image` to try and reduce runtime of the test to not build every image and clean up
		ExposedPorts: []string{"8080/tcp"},
		Env: map[string]string{
			"BOOTSTRAP_TOKEN":    bootstrapToken,
			"AUTH_DATABASE_FILE": "/auth.db",
			"AUTH_PEPPER_FILE":   "/pepper",
			"AUTH_KEY_ID":        "bartab-auth-key-001",
			"AUTH_ISSUER":        "bartab-auth",
			"AUTH_ALGORITHM":     "EdDSA",
			"AUTH_NUM_KEYS":      "1", // Start with 1 key for simpler testing
			"ENV":                "test",
			"LOG_LEVEL":          "info",
			"LOG_FORMAT":         "json",
			// Increase rate limits for E2E tests to prevent test failures
			// Tests often make many rapid requests which would otherwise hit the strict production limits
			"RATELIMIT_STRICT_REQUESTS":   "1000",
			"RATELIMIT_STRICT_WINDOW_SEC": "60",
			"RATELIMIT_STRICT_BURST":      "1000",
			"RATELIMIT_MODERATE_REQUESTS": "1000",
			"RATELIMIT_MODERATE_BURST":    "1000",
		},
		WaitingFor: wait.ForHTTP("/livez").
			WithPort("8080/tcp").
			WithStartupTimeout(60 * time.Second),
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	require.NoError(t, err)

	// Get the mapped port
	mappedPort, err := container.MappedPort(ctx, "8080")
	require.NoError(t, err)

	host, err := container.Host(ctx)
	require.NoError(t, err)

	baseURL := fmt.Sprintf("http://%s:%s", host, mappedPort.Port())

	cleanup := func() {
		if err := container.Terminate(ctx); err != nil {
			t.Logf("failed to terminate container: %v", err)
		}
	}

	return baseURL, cleanup
}

// setupAuthContainerWithDefaultRateLimits starts the auth service with DEFAULT rate limits.
// This is specifically for testing that rate limiting actually works.
// Most tests should use setupAuthContainer() which has relaxed limits to prevent test failures.
func setupAuthContainerWithDefaultRateLimits(t *testing.T) (string, func()) {
	t.Helper()
	ctx := context.Background()

	req := testcontainers.ContainerRequest{
		Image:        testImageName,
		ExposedPorts: []string{"8080/tcp"},
		Env: map[string]string{
			"BOOTSTRAP_TOKEN":    bootstrapToken,
			"AUTH_DATABASE_FILE": "/auth.db",
			"AUTH_PEPPER_FILE":   "/pepper",
			"AUTH_KEY_ID":        "bartab-auth-key-001",
			"AUTH_ISSUER":        "bartab-auth",
			"AUTH_ALGORITHM":     "EdDSA",
			"AUTH_NUM_KEYS":      "1",
			"ENV":                "test",
			"LOG_LEVEL":          "info",
			"LOG_FORMAT":         "json",
			// NOTE: No rate limit overrides - using production defaults for rate limit testing
		},
		WaitingFor: wait.ForHTTP("/livez").
			WithPort("8080/tcp").
			WithStartupTimeout(60 * time.Second),
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	require.NoError(t, err)

	// Get the mapped port
	mappedPort, err := container.MappedPort(ctx, "8080")
	require.NoError(t, err)

	host, err := container.Host(ctx)
	require.NoError(t, err)

	baseURL := fmt.Sprintf("http://%s:%s", host, mappedPort.Port())

	cleanup := func() {
		if err := container.Terminate(ctx); err != nil {
			t.Logf("failed to terminate container: %v", err)
		}
	}

	return baseURL, cleanup
}

// findRoleByName searches for a role by name and returns its ID.
func findRoleByName(t *testing.T, session *authsdk.Session, roleName string) string {
	t.Helper()

	rolesResp, err := session.ListRoles(t.Context())
	require.NoError(t, err)
	require.NotNil(t, rolesResp)
	require.NotEmpty(t, rolesResp.Roles, "Should have at least one role")

	for _, role := range rolesResp.Roles {
		if role.Name == roleName {
			return role.ID
		}
	}

	t.Fatalf("Role '%s' not found", roleName)
	return ""
}

// assertTokenResponse verifies a token response has all required fields.
func assertTokenResponse(t *testing.T, resp *authsdk.TokenResponse) {
	t.Helper()
	require.NotNil(t, resp)
	require.NotEmpty(t, resp.AccessToken, "Access token should not be empty")
	require.NotEmpty(t, resp.RefreshToken, "Refresh token should not be empty")
	require.Equal(t, "Bearer", resp.TokenType, "Token type should be Bearer")
	require.NotEmpty(t, resp.Scope, "Scope should not be empty")
}

// assertUnauthorized checks that an error indicates unauthorized access.
// This can be either a 401 HTTP status or an authorization error with invalid_grant.
func assertUnauthorized(t *testing.T, err error, context string) {
	t.Helper()
	require.Error(t, err, context)
	errMsg := err.Error()
	// Accept either HTTP 401 or authorization grant errors (invalid credentials, invalid password)
	hasUnauthorized := strings.Contains(errMsg, "401") ||
		strings.Contains(errMsg, "invalid_grant") ||
		strings.Contains(errMsg, "invalid credentials")
	require.True(t, hasUnauthorized, "%s - error should indicate unauthorized access, got: %s", context, errMsg)
}

// assertHealthy verifies a health check response is OK.
func assertHealthy(t *testing.T, health *authsdk.HealthResponse, err error) {
	t.Helper()
	require.NoError(t, err)
	require.NotNil(t, health)
	require.Equal(t, "ok", health.Status)
}

// assertScopeNotGranted verifies that a token does not contain specific scopes.
func assertScopeNotGranted(t *testing.T, tokenScope string, deniedScopes ...string) {
	t.Helper()
	for _, scope := range deniedScopes {
		require.NotContains(t, tokenScope, scope, "Should not receive %s scope", scope)
	}
}

// assertCannotAccessEndpoint verifies that an error indicates forbidden access (403 or scope error).
func assertCannotAccessEndpoint(t *testing.T, err error, context string) {
	t.Helper()
	require.Error(t, err, context)
	errMsg := err.Error()
	// Accept either server-side 403 error or client-side scope validation error
	hasForbidden := strings.Contains(errMsg, "403") || strings.Contains(errMsg, "missing required scope")
	require.True(t, hasForbidden, "Error should indicate forbidden access (403) or missing scopes, got: %s", errMsg)
}

// bootstrapService bootstraps the auth service with admin user and client.
// Returns the client ID, client secret, and admin user ID.
func bootstrapService(t *testing.T, client *authsdk.SDKClient) (clientID, clientSecret, adminUserID string) {
	t.Helper()
	ctx := context.Background()

	bootstrapReq := authsdk.BootstrapRequest{
		AdminUsername:      adminUsername,
		AdminPreferredName: adminPreferredName,
		AdminPassword:      adminPassword,
		ClientName:         clientName,
		ClientScopes:       clientScopes,
		Roles:              defaultRoleDefinitions(),
	}

	bootstrapResp, err := client.Bootstrap(ctx, bootstrapToken, bootstrapReq)
	require.NoError(t, err, "Bootstrap should succeed")
	require.NotEmpty(t, bootstrapResp.ClientID, "Client ID should not be empty")
	require.NotEmpty(t, bootstrapResp.ClientSecret, "Client secret should not be empty")
	require.NotEmpty(t, bootstrapResp.AdminUserID, "Admin user ID should not be empty")

	return bootstrapResp.ClientID, bootstrapResp.ClientSecret, bootstrapResp.AdminUserID
}

// performLogin authenticates a user with authorization code flow and returns a session.
func performLogin(t *testing.T, client *authsdk.SDKClient, clientID, clientSecret, username, password string) *authsdk.Session {
	t.Helper()
	ctx := context.Background()

	scopes := []string{"profile:read", "profile:write", "admin:read", "admin:write"}
	// Use authorization code flow with client secret
	// For server-side testing, we use a dummy redirect URI
	session, err := client.AuthorizeAndExchange(ctx, clientID, clientSecret, "http://localhost/callback", username, password, scopes)
	require.NoError(t, err, "Login should succeed")
	require.NotNil(t, session, "Session should not be nil")

	return session
}
