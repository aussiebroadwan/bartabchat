package authsdk

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/aussiebroadwan/bartab/pkg/cryptox"
)

// PKCEChallenge holds the PKCE verifier and challenge pair.
// The verifier is kept secret by the client, and the challenge is sent to the authorization endpoint.
type PKCEChallenge struct {
	// Verifier is the high-entropy cryptographic random string (kept secret)
	Verifier string

	// Challenge is the base64url-encoded SHA256 hash of the verifier (sent to server)
	Challenge string

	// Method is always "S256" for SHA256
	Method string
}

// GeneratePKCEChallenge creates a new PKCE code verifier and challenge pair.
// Uses cryptox.TokenSize256 (256 bits of entropy) and SHA256 hashing per RFC 7636.
func GeneratePKCEChallenge() (*PKCEChallenge, error) {
	verifier, err := cryptox.GenerateToken(cryptox.TokenSize256)
	if err != nil {
		return nil, fmt.Errorf("failed to generate PKCE verifier: %w", err)
	}

	// Compute S256 challenge: BASE64URL(SHA256(verifier))
	hash := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(hash[:])

	return &PKCEChallenge{
		Verifier:  verifier,
		Challenge: challenge,
		Method:    "S256",
	}, nil
}

// BuildAuthorizeURL constructs an OAuth2 authorization URL for the authorization code flow.
// This URL should be used to redirect the user's browser to begin the authorization flow.
//
// Parameters:
//   - redirectURI: The URI to redirect back to after authorization (must match registered redirect URI)
//   - state: Opaque value used to maintain state between request and callback (recommended for CSRF protection)
//   - scopes: List of scopes to request (optional, will use client's default scopes if empty)
//   - pkce: PKCE challenge (optional but highly recommended, required for public clients)
//
// Example:
//
//	pkce, _ := authsdk.GeneratePKCEChallenge()
//	url := client.BuildAuthorizeURL("cli-app", "https://localhost/callback", "random-state", []string{"profile:read"}, pkce)
//	// Store pkce.Verifier securely for later use in ExchangeAuthorizationCode
//	// Redirect user's browser to url
func (c *SDKClient) BuildAuthorizeURL(
	clientID, redirectURI, state string,
	scopes []string,
	pkce *PKCEChallenge,
) string {
	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", clientID)
	params.Set("redirect_uri", redirectURI)

	if state != "" {
		params.Set("state", state)
	}

	if len(scopes) > 0 {
		params.Set("scope", strings.Join(scopes, " "))
	}

	if pkce != nil {
		params.Set("code_challenge", pkce.Challenge)
		params.Set("code_challenge_method", pkce.Method)
	}

	return fmt.Sprintf("%s/v1/oauth2/authorize?%s", c.BaseURL, params.Encode())
}

// AuthorizeWithBearerToken performs authorization using an existing access token.
// This is useful when a user already has a valid session and wants to authorize
// a new client or request different scopes without re-entering credentials.
//
// The access token is sent via Authorization: Bearer header (POST method). The server will verify
// the token and issue an authorization code if valid.
//
// Returns the authorization code on success.
func (c *SDKClient) AuthorizeWithBearerToken(
	ctx context.Context,
	accessToken string,
	clientID, redirectURI string,
	scopes []string,
	pkce *PKCEChallenge,
) (string, error) {
	data := url.Values{
		"response_type": {"code"},
		"client_id":     {clientID},
		"redirect_uri":  {redirectURI},
	}

	if len(scopes) > 0 {
		data.Set("scope", strings.Join(scopes, " "))
	}

	if pkce != nil {
		data.Set("code_challenge", pkce.Challenge)
		data.Set("code_challenge_method", pkce.Method)
	}

	// Create HTTP client that doesn't follow redirects
	noRedirectClient := &http.Client{
		Timeout: c.HTTPClient.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		c.BaseURL+"/v1/oauth2/authorize",
		strings.NewReader(data.Encode()),
	)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := noRedirectClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// Read response body for error details
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}

	// Check for redirect (success case)
	if resp.StatusCode == http.StatusFound {
		location := resp.Header.Get("Location")
		if location == "" {
			return "", fmt.Errorf("redirect response missing Location header")
		}

		// Parse the redirect URL and extract the code
		redirectURL, err := url.Parse(location)
		if err != nil {
			return "", fmt.Errorf("failed to parse redirect URL: %w", err)
		}

		code := redirectURL.Query().Get("code")
		if code == "" {
			// Check for error in redirect
			errorCode := redirectURL.Query().Get("error")
			errorDesc := redirectURL.Query().Get("error_description")
			if errorCode != "" {
				return "", fmt.Errorf("authorization failed: %s - %s", errorCode, errorDesc)
			}
			return "", fmt.Errorf("redirect missing authorization code")
		}

		return code, nil
	}

	// Handle other error status codes
	return "", fmt.Errorf(
		"authorize request failed with status %d: %s",
		resp.StatusCode,
		string(bodyBytes),
	)
}

// AuthorizeWithPassword performs an interactive authorization using username and password.
// This is useful for server-side flows where you can collect credentials directly.
//
// This method sends credentials via POST to the authorize endpoint and follows redirects
// to obtain the authorization code. If MFA is required, returns *MFARequiredError.
//
// Returns the authorization code on success.
func (c *SDKClient) AuthorizeWithPassword(
	ctx context.Context,
	clientID, redirectURI, username, password string,
	scopes []string,
	pkce *PKCEChallenge,
) (string, error) {
	data := url.Values{
		"response_type": {"code"},
		"client_id":     {clientID},
		"redirect_uri":  {redirectURI},
		"username":      {username},
		"password":      {password},
	}

	if len(scopes) > 0 {
		data.Set("scope", strings.Join(scopes, " "))
	}

	if pkce != nil {
		data.Set("code_challenge", pkce.Challenge)
		data.Set("code_challenge_method", pkce.Method)
	}

	// Create HTTP client that doesn't follow redirects
	noRedirectClient := &http.Client{
		Timeout: c.HTTPClient.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		c.BaseURL+"/v1/oauth2/authorize",
		strings.NewReader(data.Encode()),
	)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := noRedirectClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// Read response body for error details
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}

	// Check for 409 Conflict (MFA required)
	if resp.StatusCode == http.StatusConflict {
		var mfaResp struct {
			Error            string   `json:"error"`
			ErrorDescription string   `json:"error_description"`
			MFAToken         string   `json:"mfa_token"`
			MFAMethods       []string `json:"mfa_methods"`
		}
		if err := json.Unmarshal(bodyBytes, &mfaResp); err != nil {
			return "", fmt.Errorf("failed to decode MFA response: %w", err)
		}

		return "", &MFARequiredError{
			MFAToken: mfaResp.MFAToken,
			Methods:  mfaResp.MFAMethods,
		}
	}

	// Check for redirect (success case)
	if resp.StatusCode == http.StatusFound {
		location := resp.Header.Get("Location")
		if location == "" {
			return "", fmt.Errorf("redirect response missing Location header")
		}

		// Parse the redirect URL and extract the code
		redirectURL, err := url.Parse(location)
		if err != nil {
			return "", fmt.Errorf("failed to parse redirect URL: %w", err)
		}

		code := redirectURL.Query().Get("code")
		if code == "" {
			// Check for error in redirect
			errorCode := redirectURL.Query().Get("error")
			errorDesc := redirectURL.Query().Get("error_description")
			if errorCode != "" {
				return "", fmt.Errorf("authorization failed: %s - %s", errorCode, errorDesc)
			}
			return "", fmt.Errorf("redirect missing authorization code")
		}

		return code, nil
	}

	// Handle other error status codes
	return "", fmt.Errorf(
		"authorize request failed with status %d: %s",
		resp.StatusCode,
		string(bodyBytes),
	)
}

// AuthorizeWithPasswordAndMFA completes authorization with MFA verification.
// Use this after receiving an *MFARequiredError from AuthorizeWithPassword.
//
// Returns the authorization code on success.
func (c *SDKClient) AuthorizeWithPasswordAndMFA(
	ctx context.Context,
	clientID, redirectURI string,
	mfaError MFARequiredError,
	method, code string,
	scopes []string,
	pkce *PKCEChallenge,
) (string, error) {
	data := url.Values{
		"response_type": {"code"},
		"client_id":     {clientID},
		"redirect_uri":  {redirectURI},
		"mfa_token":     {mfaError.MFAToken},
		"mfa_method":    {method},
		"mfa_code":      {code},
	}

	if len(scopes) > 0 {
		data.Set("scope", strings.Join(scopes, " "))
	}

	if pkce != nil {
		data.Set("code_challenge", pkce.Challenge)
		data.Set("code_challenge_method", pkce.Method)
	}

	// Create HTTP client that doesn't follow redirects
	noRedirectClient := &http.Client{
		Timeout: c.HTTPClient.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		c.BaseURL+"/v1/oauth2/authorize",
		strings.NewReader(data.Encode()),
	)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := noRedirectClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// Check for redirect (success case)
	if resp.StatusCode == http.StatusFound {
		location := resp.Header.Get("Location")
		if location == "" {
			return "", fmt.Errorf("redirect response missing Location header")
		}

		// Parse the redirect URL and extract the code
		redirectURL, err := url.Parse(location)
		if err != nil {
			return "", fmt.Errorf("failed to parse redirect URL: %w", err)
		}

		authCode := redirectURL.Query().Get("code")
		if authCode == "" {
			// Check for error in redirect
			errorCode := redirectURL.Query().Get("error")
			errorDesc := redirectURL.Query().Get("error_description")
			if errorCode != "" {
				return "", fmt.Errorf("authorization failed: %s - %s", errorCode, errorDesc)
			}
			return "", fmt.Errorf("redirect missing authorization code")
		}

		return authCode, nil
	}

	// Handle error responses
	bodyBytes, _ := io.ReadAll(resp.Body)
	return "", fmt.Errorf(
		"authorize MFA request failed with status %d: %s",
		resp.StatusCode,
		string(bodyBytes),
	)
}

// ExchangeAuthorizationCode exchanges an authorization code for tokens.
// This completes the authorization code flow by trading the code for an access token and refresh token.
//
// Parameters:
//   - clientID: The OAuth2 client ID
//   - clientSecret: The client secret (only for confidential clients, use empty string for public clients)
//   - code: The authorization code received from the authorize endpoint
//   - redirectURI: Must match the redirect_uri used in the authorization request
//   - codeVerifier: The PKCE verifier from the original PKCEChallenge (optional, but required if PKCE was used)
//
// Example:
//
//	pkce, _ := authsdk.GeneratePKCEChallenge()
//	// ... user authorizes and you receive authorization code ...
//	tokens, err := client.ExchangeAuthorizationCode(ctx, clientID, "", authCode, redirectURI, pkce.Verifier)
func (c *SDKClient) ExchangeAuthorizationCode(
	ctx context.Context,
	clientID, clientSecret, code, redirectURI, codeVerifier string,
) (*TokenResponse, error) {
	data := url.Values{
		"grant_type":   {"authorization_code"},
		"client_id":    {clientID},
		"code":         {code},
		"redirect_uri": {redirectURI},
	}

	if clientSecret != "" {
		data.Set("client_secret", clientSecret)
	}

	if codeVerifier != "" {
		data.Set("code_verifier", codeVerifier)
	}

	return c.requestToken(ctx, data)
}

// AuthorizeAndExchange is a convenience method that combines authorization and token exchange.
// This performs the complete authorization code flow in one call using password credentials.
//
// If MFA is required, returns *MFARequiredError. You must then call AuthorizeAndExchangeWithMFA.
//
// Returns an authenticated Session on success.
func (c *SDKClient) AuthorizeAndExchange(
	ctx context.Context,
	clientID, clientSecret, redirectURI, username, password string,
	scopes []string,
) (*Session, error) {
	// Generate PKCE challenge
	pkce, err := GeneratePKCEChallenge()
	if err != nil {
		return nil, fmt.Errorf("failed to generate PKCE: %w", err)
	}

	// Get authorization code
	authCode, err := c.AuthorizeWithPassword(ctx, clientID, redirectURI, username, password, scopes, pkce)
	if err != nil {
		return nil, err
	}

	// Exchange code for tokens
	tokenResp, err := c.ExchangeAuthorizationCode(ctx, clientID, clientSecret, authCode, redirectURI, pkce.Verifier)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange authorization code: %w", err)
	}

	return newSession(c, clientID, tokenResp), nil
}

// AuthorizeAndExchangeWithMFA completes the authorization code flow with MFA verification.
// Use this after receiving *MFARequiredError from AuthorizeAndExchange.
//
// Returns an authenticated Session on success.
func (c *SDKClient) AuthorizeAndExchangeWithMFA(
	ctx context.Context,
	clientID, clientSecret, redirectURI string,
	mfaError MFARequiredError,
	method, mfaCode string,
	scopes []string,
) (*Session, error) {
	// Generate PKCE challenge
	pkce, err := GeneratePKCEChallenge()
	if err != nil {
		return nil, fmt.Errorf("failed to generate PKCE: %w", err)
	}

	// Complete MFA and get authorization code
	authCode, err := c.AuthorizeWithPasswordAndMFA(ctx, clientID, redirectURI, mfaError, method, mfaCode, scopes, pkce)
	if err != nil {
		return nil, err
	}

	// Exchange code for tokens
	tokenResp, err := c.ExchangeAuthorizationCode(ctx, clientID, clientSecret, authCode, redirectURI, pkce.Verifier)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange authorization code: %w", err)
	}

	return newSession(c, clientID, tokenResp), nil
}

// AuthorizeViaRedirect performs authorization using an existing session via redirect.
// This is the standard OAuth2 browser-based flow where the user already has a session
// (via cookie or Bearer token) and the authorization endpoint is accessed via redirect.
//
// This method is useful for:
// - Browser-based flows where session is maintained via cookies
// - Applications that want to use the standard OAuth2 redirect pattern
// - SSO scenarios where the user is already authenticated
//
// The session can be provided via:
// - accessToken: Sent as Authorization: Bearer header
// - sessionCookie: Sent as HTTP cookie (name: bartab_session)
//
// Use empty string for accessToken to rely only on sessionCookie, or vice versa.
//
// Returns the authorization code on success, or an error if the session is invalid
// or the user needs to authenticate.
func (c *SDKClient) AuthorizeViaRedirect(
	ctx context.Context,
	accessToken, sessionCookie string,
	clientID, redirectURI string,
	scopes []string,
	pkce *PKCEChallenge,
) (string, error) {
	// Build the authorization URL
	authURL := c.BuildAuthorizeURL(clientID, redirectURI, "", scopes, pkce)

	// Create HTTP client that doesn't follow redirects
	noRedirectClient := &http.Client{
		Timeout: c.HTTPClient.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, authURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	// Set Bearer token if provided
	if accessToken != "" {
		req.Header.Set("Authorization", "Bearer "+accessToken)
	}

	// Set session cookie if provided
	if sessionCookie != "" {
		req.AddCookie(&http.Cookie{
			Name:  "bartab_session",
			Value: sessionCookie,
		})
	}

	resp, err := noRedirectClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// Read response body for error details
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}

	// Check for redirect (success case)
	if resp.StatusCode == http.StatusFound {
		location := resp.Header.Get("Location")
		if location == "" {
			return "", fmt.Errorf("redirect response missing Location header")
		}

		// Parse the redirect URL and extract the code
		redirectURL, err := url.Parse(location)
		if err != nil {
			return "", fmt.Errorf("failed to parse redirect URL: %w", err)
		}

		code := redirectURL.Query().Get("code")
		if code == "" {
			// Check for error in redirect
			errorCode := redirectURL.Query().Get("error")
			errorDesc := redirectURL.Query().Get("error_description")
			if errorCode != "" {
				return "", fmt.Errorf("authorization failed: %s - %s", errorCode, errorDesc)
			}
			return "", fmt.Errorf("redirect missing authorization code")
		}

		return code, nil
	}

	// Handle 401 Unauthorized (session required)
	if resp.StatusCode == http.StatusUnauthorized {
		return "", fmt.Errorf("authentication required: %s", string(bodyBytes))
	}

	// Handle other error status codes
	return "", fmt.Errorf(
		"authorize request failed with status %d: %s",
		resp.StatusCode,
		string(bodyBytes),
	)
}

// AuthorizeAndExchangeViaRedirect is a convenience method that combines redirect authorization
// with an existing session and token exchange. This completes the authorization code flow
// using the standard OAuth2 redirect pattern.
//
// Use this when you have an existing session (access token or session cookie) and want to
// obtain a new authorization with potentially different scopes.
//
// Returns an authenticated Session on success.
func (c *SDKClient) AuthorizeAndExchangeViaRedirect(
	ctx context.Context,
	accessToken, sessionCookie string,
	clientID, clientSecret, redirectURI string,
	scopes []string,
) (*Session, error) {
	// Generate PKCE challenge
	pkce, err := GeneratePKCEChallenge()
	if err != nil {
		return nil, fmt.Errorf("failed to generate PKCE: %w", err)
	}

	// Get authorization code using redirect
	authCode, err := c.AuthorizeViaRedirect(ctx, accessToken, sessionCookie, clientID, redirectURI, scopes, pkce)
	if err != nil {
		return nil, err
	}

	// Exchange code for tokens
	tokenResp, err := c.ExchangeAuthorizationCode(ctx, clientID, clientSecret, authCode, redirectURI, pkce.Verifier)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange authorization code: %w", err)
	}

	return newSession(c, clientID, tokenResp), nil
}

// ParseAuthorizationCallback parses the callback URL from an authorization redirect.
// This extracts the authorization code and state from the redirect URL query parameters.
//
// Returns the authorization code and state, or an error if the callback contains an error response.
//
// Example:
//
//	code, state, err := authsdk.ParseAuthorizationCallback("https://localhost/callback?code=xyz&state=abc")
//	if err != nil {
//	    // Handle error (e.g., user denied authorization)
//	}
//	// Verify state matches what you sent
//	// Exchange code for tokens using ExchangeAuthorizationCode
func ParseAuthorizationCallback(callbackURL string) (code, state string, err error) {
	u, err := url.Parse(callbackURL)
	if err != nil {
		return "", "", fmt.Errorf("failed to parse callback URL: %w", err)
	}

	query := u.Query()

	// Check for error response
	if errorCode := query.Get("error"); errorCode != "" {
		errorDesc := query.Get("error_description")
		return "", "", fmt.Errorf("authorization error: %s - %s", errorCode, errorDesc)
	}

	// Extract code and state
	code = query.Get("code")
	if code == "" {
		return "", "", fmt.Errorf("callback missing authorization code")
	}

	state = query.Get("state")

	return code, state, nil
}
