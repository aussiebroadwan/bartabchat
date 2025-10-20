package authsdk

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// EnrollTOTP initiates TOTP enrollment for the authenticated user.
// Requires: profile:write scope
// Automatically refreshes the access token if expired.
func (s *Session) EnrollTOTP(ctx context.Context) (*TOTPEnrollResponse, error) {
	if err := s.checkScopes("profile:write"); err != nil {
		return nil, err
	}

	token, err := s.getValidToken(ctx)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, s.client.BaseURL+"/v1/mfa/totp/enroll", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+token)

	resp, err := s.client.HTTPClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("enroll request failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var enrollResp TOTPEnrollResponse
	if err := json.NewDecoder(resp.Body).Decode(&enrollResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &enrollResp, nil
}

// VerifyTOTP verifies a TOTP code and completes MFA enrollment.
// Requires: profile:write scope
// Automatically refreshes the access token if expired.
func (s *Session) VerifyTOTP(ctx context.Context, code string) (*BackupCodesResponse, error) {
	if err := s.checkScopes("profile:write"); err != nil {
		return nil, err
	}

	token, err := s.getValidToken(ctx)
	if err != nil {
		return nil, err
	}

	reqBody := TOTPVerifyRequest{Code: code}
	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, s.client.BaseURL+"/v1/mfa/totp/verify", bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+token)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := s.client.HTTPClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("verify request failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var backupResp BackupCodesResponse
	if err := json.NewDecoder(resp.Body).Decode(&backupResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &backupResp, nil
}

// RegenerateBackupCodes generates new backup codes for the authenticated user.
// Requires: profile:write scope
// Requires a valid TOTP code for verification.
// Automatically refreshes the access token if expired.
func (s *Session) RegenerateBackupCodes(ctx context.Context, totpCode string) (*BackupCodesResponse, error) {
	if err := s.checkScopes("profile:write"); err != nil {
		return nil, err
	}

	token, err := s.getValidToken(ctx)
	if err != nil {
		return nil, err
	}

	reqBody := BackupCodesRegenerateRequest{Code: totpCode}
	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, s.client.BaseURL+"/v1/mfa/backup-codes", bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+token)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := s.client.HTTPClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("regenerate backup codes request failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var backupResp BackupCodesResponse
	if err := json.NewDecoder(resp.Body).Decode(&backupResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &backupResp, nil
}

// RemoveMFA removes MFA from the authenticated user's account.
// Requires: profile:write scope
// Requires a valid TOTP code for verification.
// Automatically refreshes the access token if expired.
func (s *Session) RemoveMFA(ctx context.Context, totpCode string) error {
	if err := s.checkScopes("profile:write"); err != nil {
		return err
	}

	token, err := s.getValidToken(ctx)
	if err != nil {
		return err
	}

	reqBody := TOTPRemoveRequest{Code: totpCode}
	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodDelete, s.client.BaseURL+"/v1/mfa/totp", bytes.NewReader(bodyBytes))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+token)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := s.client.HTTPClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("remove MFA request failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	return nil
}
