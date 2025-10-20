package authsdk

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// RefreshGrant requests new tokens using a refresh token.
func (c *SDKClient) RefreshGrant(
	ctx context.Context,
	clientID, refreshToken string,
) (*TokenResponse, error) {
	data := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {clientID},
	}

	return c.requestToken(ctx, data)
}

// ClientCredentialsGrant requests an access token using the OAuth2 client_credentials grant.
// This grant is used for machine-to-machine (M2M) authentication where a client authenticates
// as itself (not on behalf of a user). The client must be confidential (have a secret).
//
// Note: This grant does NOT return a refresh token, clients can re-authenticate anytime. But
// the idea is the client only should do short lived operations with the access token.
func (c *SDKClient) ClientCredentialsGrant(
	ctx context.Context,
	clientID, clientSecret string,
	scopes []string,
) (*TokenResponse, error) {
	data := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
	}
	if len(scopes) > 0 {
		data.Set("scope", strings.Join(scopes, " "))
	}

	return c.requestToken(ctx, data)
}

// MFAOTPGrant completes MFA authentication using a TOTP code or backup code.
func (c *SDKClient) MFAOTPGrant(
	ctx context.Context,
	mfaError MFARequiredError,
	method, otpCode string,
) (*TokenResponse, error) {
	data := url.Values{
		"grant_type": {"mfa_otp"},
		"mfa_token":  {mfaError.MFAToken},
		"method":     {method},
		"otp_code":   {otpCode},
	}

	return c.requestToken(ctx, data)
}

// RevokeToken revokes a refresh token.
func (c *SDKClient) RevokeToken(ctx context.Context, clientID, token string) error {
	data := url.Values{
		"token":     {token},
		"client_id": {clientID},
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		c.BaseURL+"/v1/oauth2/revoke",
		strings.NewReader(data.Encode()),
	)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf(
			"revoke request failed with status %d: %s",
			resp.StatusCode,
			string(bodyBytes),
		)
	}

	return nil
}

func (c *SDKClient) requestToken(ctx context.Context, data url.Values) (*TokenResponse, error) {
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		c.BaseURL+"/v1/oauth2/token",
		strings.NewReader(data.Encode()),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf(
			"token request failed with status %d: %s",
			resp.StatusCode,
			string(bodyBytes),
		)
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &tokenResp, nil
}
