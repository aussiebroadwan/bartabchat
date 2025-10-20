package auth_test

import (
	"testing"

	"github.com/aussiebroadwan/bartab/pkg/authsdk"
)

// TestBootstrapSuccess verifies successful bootstrap creates admin user and client.
func TestBootstrapSuccess(t *testing.T) {
	baseURL, cleanup := setupAuthContainer(t)
	defer cleanup()

	client := authsdk.NewSDKClient(baseURL)

	clientID, _, adminUserID := bootstrapService(t, client)

	t.Logf("Bootstrap successful")
	t.Logf("Admin User ID: %s", adminUserID)
	t.Logf("Client ID: %s", clientID)
}

// TestBootstrapIdempotency verifies that bootstrap can only be called once.
func TestBootstrapIdempotency(t *testing.T) {
	baseURL, cleanup := setupAuthContainer(t)
	defer cleanup()

	client := authsdk.NewSDKClient(baseURL)

	// First bootstrap should succeed
	clientID, _, adminUserID := bootstrapService(t, client)

	t.Logf("First bootstrap successful")
	t.Logf("Admin User ID: %s", adminUserID)
	t.Logf("Client ID: %s", clientID)

	// Second bootstrap should fail with 401
	_, err := client.Bootstrap(t.Context(), bootstrapToken, authsdk.BootstrapRequest{
		AdminUsername:      "another-admin",
		AdminPreferredName: "Another Admin",
		AdminPassword:      "AnotherPassword123!",
		ClientName:         "another-client",
		ClientScopes:       []string{"app:read"},
		Roles:              defaultRoleDefinitions(),
	})

	assertUnauthorized(t, err, "Second bootstrap should be rejected")

	t.Logf("Second bootstrap correctly rejected")
}
