package service

import (
	"context"
	"errors"
	"fmt"

	"github.com/aussiebroadwan/bartab/internal/auth/domain"
	"github.com/aussiebroadwan/bartab/internal/auth/store"
	"github.com/aussiebroadwan/bartab/pkg/cryptox"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

const (
	backupCodeCount = 10                   // Number of backup codes to generate
	backupCodeBytes = cryptox.TokenSize128 // 128-bit entropy for backup codes
)

var (
	ErrInvalidTOTPCode   = errors.New("invalid TOTP code")
	ErrMFANotEnabled     = errors.New("MFA not enabled for this user")
	ErrMFAAlreadyEnabled = errors.New("MFA already enabled for this user")
)

type MFAService struct {
	Store  store.Store
	Issuer string // Issuer name for TOTP (e.g., "BarTab")
}

// EnrollTOTP generates a TOTP secret for the user and returns it along with a QR code.
// This does NOT enable MFA yet - the user must verify the code first.
func (s *MFAService) EnrollTOTP(ctx context.Context, userID string, username string) (domain.MFAEnrollResponse, error) {
	// Check if MFA is already enabled
	_, mfaSecret, err := s.Store.Users().GetMFAInfo(ctx, userID)
	if err != nil {
		return domain.MFAEnrollResponse{}, fmt.Errorf("failed to get MFA info: %w", err)
	}
	if mfaSecret != nil && *mfaSecret != "" {
		return domain.MFAEnrollResponse{}, ErrMFAAlreadyEnabled
	}

	// Generate TOTP key
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      s.Issuer,
		AccountName: username,
		Period:      30,
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA1,
	})
	if err != nil {
		return domain.MFAEnrollResponse{}, fmt.Errorf("failed to generate TOTP key: %w", err)
	}

	// Store the secret (but don't enable MFA yet)
	if err := s.Store.Users().UpdateMFASecret(ctx, userID, key.Secret()); err != nil {
		return domain.MFAEnrollResponse{}, fmt.Errorf("failed to store MFA secret: %w", err)
	}

	return domain.MFAEnrollResponse{
		Secret:  key.Secret(),
		QRCode:  key.URL(),
		Issuer:  s.Issuer,
		Account: username,
	}, nil
}

// VerifyTOTP verifies a TOTP code and enables MFA for the user if valid.
// It also generates backup codes and stores them.
func (s *MFAService) VerifyTOTP(ctx context.Context, userID string, code string) ([]string, error) {
	// Get user's MFA info
	mfaEnabledStr, mfaSecret, err := s.Store.Users().GetMFAInfo(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get MFA info: %w", err)
	}

	// Check if MFA secret exists
	if mfaSecret == nil || *mfaSecret == "" {
		return nil, errors.New("MFA not enrolled - call EnrollTOTP first")
	}

	// Check if MFA is already enabled
	if mfaEnabledStr != nil && *mfaEnabledStr != "" {
		return nil, ErrMFAAlreadyEnabled
	}

	// Verify the TOTP code
	valid := totp.Validate(code, *mfaSecret)
	if !valid {
		return nil, ErrInvalidTOTPCode
	}

	// Generate backup codes
	backupCodes := make([]string, backupCodeCount)
	for i := range backupCodeCount {
		code, err := cryptox.GenerateToken(backupCodeBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to generate backup code: %w", err)
		}
		backupCodes[i] = code
	}

	// Store backup codes and enable MFA in a transaction
	err = s.Store.WithTx(ctx, func(tx store.Tx) error {
		// Store backup codes as hashes
		for _, code := range backupCodes {
			hash := cryptox.FingerprintToken(code)
			if err := tx.BackupCodes().CreateBackupCode(ctx, userID, hash); err != nil {
				return fmt.Errorf("failed to store backup code: %w", err)
			}
		}

		// Enable MFA
		if err := tx.Users().EnableMFA(ctx, userID); err != nil {
			return fmt.Errorf("failed to enable MFA: %w", err)
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return backupCodes, nil
}

// RegenerateBackupCodes generates new backup codes after verifying a TOTP code.
func (s *MFAService) RegenerateBackupCodes(ctx context.Context, userID string, totpCode string) ([]string, error) {
	// Verify TOTP code first
	if err := s.verifyTOTPCode(ctx, userID, totpCode); err != nil {
		return nil, err
	}

	// Generate new backup codes
	backupCodes := make([]string, backupCodeCount)
	for i := range backupCodeCount {
		code, err := cryptox.GenerateToken(backupCodeBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to generate backup code: %w", err)
		}
		backupCodes[i] = code
	}

	// Replace old backup codes with new ones in a transaction
	err := s.Store.WithTx(ctx, func(tx store.Tx) error {
		// Delete all old backup codes
		if err := tx.BackupCodes().DeleteAllBackupCodes(ctx, userID); err != nil {
			return fmt.Errorf("failed to delete old backup codes: %w", err)
		}

		// Store new backup codes as hashes
		for _, code := range backupCodes {
			hash := cryptox.FingerprintToken(code)
			if err := tx.BackupCodes().CreateBackupCode(ctx, userID, hash); err != nil {
				return fmt.Errorf("failed to store backup code: %w", err)
			}
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return backupCodes, nil
}

// RemoveMFA removes MFA for a user after verifying a TOTP code.
func (s *MFAService) RemoveMFA(ctx context.Context, userID string, totpCode string) error {
	// Verify TOTP code first
	if err := s.verifyTOTPCode(ctx, userID, totpCode); err != nil {
		return err
	}

	// Remove MFA and backup codes in a transaction
	return s.Store.WithTx(ctx, func(tx store.Tx) error {
		// Delete all backup codes
		if err := tx.BackupCodes().DeleteAllBackupCodes(ctx, userID); err != nil {
			return fmt.Errorf("failed to delete backup codes: %w", err)
		}

		// Disable MFA
		if err := tx.Users().DisableMFA(ctx, userID); err != nil {
			return fmt.Errorf("failed to disable MFA: %w", err)
		}

		return nil
	})
}

// verifyTOTPCode is a helper that verifies a TOTP code for a user.
func (s *MFAService) verifyTOTPCode(ctx context.Context, userID string, code string) error {
	// Get user's MFA info
	mfaEnabledStr, mfaSecret, err := s.Store.Users().GetMFAInfo(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to get MFA info: %w", err)
	}

	// Check if MFA is enabled
	if mfaEnabledStr == nil || *mfaEnabledStr == "" {
		return ErrMFANotEnabled
	}

	// Check if MFA secret exists
	if mfaSecret == nil || *mfaSecret == "" {
		return ErrMFANotEnabled
	}

	// Verify the TOTP code
	valid := totp.Validate(code, *mfaSecret)
	if !valid {
		return ErrInvalidTOTPCode
	}

	return nil
}
