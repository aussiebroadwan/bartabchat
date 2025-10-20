/*
Package authsdk provides a client SDK for interacting with the BarTab authentication service.

# Overview

The authsdk package implements an OAuth2-compliant client for the BarTab authentication
service. It provides both unauthenticated operations (via SDKClient) and authenticated
operations (via Session) with automatic token refresh.

# SDKClient vs Session

The package is organized around two main types:

  - SDKClient: Provides unauthenticated operations and creates authenticated sessions
  - Session: Provides authenticated operations with automatic token refresh

Create an SDKClient to interact with public endpoints and initiate authentication flows:

	client := authsdk.NewSDKClient("https://auth.example.com")

	// Check service health
	health, err := client.GetLiveness(ctx)

	// Bootstrap the service (one-time setup)
	bootstrap, err := client.Bootstrap(ctx, token, req)

	// Authenticate to create a session
	session, err := client.AuthenticateWithPassword(ctx, clientID, username, password, scopes)

Use a Session for authenticated operations. Sessions automatically handle token expiration
and refresh:

	// Get user information (requires profile:read scope)
	userInfo, err := session.GetUserInfo(ctx)

	// Mint an invite (requires admin:write scope)
	invite, err := session.MintInvite(ctx, req)

	// List roles (requires admin:read scope)
	roles, err := session.ListRoles(ctx)

# Authentication Flows

The SDK supports multiple OAuth2 grant types:

Password Grant:

	session, err := client.AuthenticateWithPassword(ctx, clientID, username, password, scopes)
	if mfaErr, ok := err.(*authsdk.MFARequiredError); ok {
		// MFA required, complete with TOTP code
		tokenResp, err := client.MFAOTPGrant(ctx, *mfaErr, "totp", otpCode)
		session = client.NewSessionFromTokens(clientID, tokenResp.AccessToken, ...)
	}

Client Credentials Grant (M2M):

	session, err := client.AuthenticateWithClientCredentials(ctx, clientID, clientSecret, scopes)

Refresh Token Grant:

	session, err := client.AuthenticateWithRefreshToken(ctx, clientID, refreshToken)

# Automatic Token Refresh

Sessions automatically refresh access tokens when they expire. All Session methods
call getValidToken() internally, which:

 1. Checks if the access token is still valid (with 30-second buffer)
 2. If expired, uses the refresh token to obtain a new access token
 3. Updates the session with the new tokens and scopes

You never need to manually refresh tokens when using Session methods.

# Scope Requirements

Each authenticated operation requires specific scopes. The SDK enforces scope requirements
both client-side (before making requests) and server-side. Standard scopes include:

  - profile:read: Read user profile information
  - profile:write: Update user profile information
  - admin:read: Read admin information (roles, clients, etc.)
  - admin:write: Perform admin actions (create invites, manage clients, etc.)

Client-side scope checking is enabled by default but can be disabled for testing:

	client := authsdk.NewSDKClient("https://auth.example.com")
	client.CheckScopes = false // Disable client-side scope checking

# Session Organization

Session methods are organized into three files based on their purpose:

  - session.go: Core session management, token refresh, scope checking
  - session_admin.go: Admin operations (invites, clients, roles)
  - session_user.go: User operations (userinfo, introspect, revoke)

# Error Handling

The SDK returns typed errors for specific conditions:

  - MFARequiredError: MFA is required to complete authentication
  - Standard errors: Network errors, validation errors, HTTP errors

Example:

	session, err := client.AuthenticateWithPassword(ctx, clientID, username, password, scopes)
	if err != nil {
		if mfaErr, ok := err.(*authsdk.MFARequiredError); ok {
			// Handle MFA requirement
			fmt.Println("MFA required, methods:", mfaErr.Methods)
		} else {
			// Handle other errors
			return err
		}
	}

# Bootstrap

The Bootstrap operation is a one-time setup that creates the initial admin user,
OAuth2 client, and role definitions:

	req := authsdk.BootstrapRequest{
		AdminUsername:      "admin",
		AdminPreferredName: "Administrator",
		AdminPassword:      "secure-password",
		ClientName:         "admin-client",
		ClientScopes:       []string{"profile:read", "profile:write", "admin:read", "admin:write"},
		Roles: []authsdk.RoleDefinition{
			{
				Name:   "admin",
				Scopes: []string{"profile:read", "profile:write", "admin:read", "admin:write"},
			},
			{
				Name:   "user",
				Scopes: []string{"profile:read", "profile:write"},
			},
		},
	}

	// Validate before sending
	if errs := req.Validate(); errs != nil {
		// Handle validation errors
		for field, msg := range errs {
			fmt.Printf("%s: %s\n", field, msg)
		}
		return
	}

	bootstrap, err := client.Bootstrap(ctx, bootstrapToken, req)

# Thread Safety

Sessions are safe for concurrent use. All Session methods use read/write locks to
protect access to tokens and scopes. Multiple goroutines can share a single Session
and make authenticated requests concurrently.

# Examples

Complete authentication and API usage:

	// Create client
	client := authsdk.NewSDKClient("https://auth.example.com")

	// Authenticate
	session, err := client.AuthenticateWithPassword(
		context.Background(),
		"client-id",
		"username",
		"password",
		[]string{"profile:read", "admin:read"},
	)
	if err != nil {
		log.Fatal(err)
	}

	// Use authenticated session
	userInfo, err := session.GetUserInfo(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Logged in as: %s\n", userInfo.Username)

	// Session automatically refreshes tokens when needed
	roles, err := session.ListRoles(context.Background())
	if err != nil {
		log.Fatal(err)
	}

	// Revoke session when done
	err = session.Revoke(context.Background())
*/
package authsdk
