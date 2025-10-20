package service

import (
	"context"
	"fmt"
	"time"

	"github.com/aussiebroadwan/bartab/internal/auth/domain"
	"github.com/aussiebroadwan/bartab/internal/auth/store"
	"github.com/aussiebroadwan/bartab/pkg/cryptox"
	"github.com/aussiebroadwan/bartab/pkg/idx"
	"github.com/aussiebroadwan/bartab/pkg/jwtx"
)

// KeyRotationService handles JWT signing key rotation for both ephemeral and persistent modes.
// It allows manual rotation and retirement of signing keys at runtime.
//
// In ephemeral mode (Store == nil):
//   - Keys are added to KeyManager in-memory only
//   - Retired keys remain in KeySet for verification until restart
//   - No database persistence
//
// In persistent mode (Store != nil):
//   - Keys are encrypted and stored in database
//   - Retired keys have grace period for verification
//   - Keys survive service restarts
type KeyRotationService struct {
	Store       store.Store      // nil for ephemeral mode
	KeyManager  *jwtx.KeyManager // Required for both modes
	Algorithm   string
	RSABits     int
	GracePeriod time.Duration
}

// RotateKeyRequest represents a request to rotate signing keys.
type RotateKeyRequest struct {
	// RetireExisting will mark current active keys as retired if true.
	// If false, new key is added alongside existing keys.
	RetireExisting bool
}

// RotateKeyResponse represents the result of a key rotation operation.
type RotateKeyResponse struct {
	NewKey      domain.SigningKey   `json:"new_key"`
	RetiredKeys []domain.SigningKey `json:"retired_keys,omitempty"`
	ActiveKeys  int                 `json:"active_keys"`
}

// RotateKey generates a new signing key and optionally retires existing keys.
// Works in both ephemeral and persistent modes.
func (s *KeyRotationService) RotateKey(ctx context.Context, req RotateKeyRequest) (*RotateKeyResponse, error) {
	if s.KeyManager == nil {
		return nil, fmt.Errorf("KeyManager is required")
	}

	// Generate random key ID
	kid, err := generateRandomKeyID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate key ID: %w", err)
	}

	// Generate new key pair
	var pemData []byte
	switch s.Algorithm {
	case jwtx.AlgorithmRS256:
		rsaBits := s.RSABits
		if rsaBits == 0 {
			rsaBits = 4096
		}
		pemData, err = cryptox.GenerateRSAKey(rsaBits)
	case jwtx.AlgorithmES256:
		pemData, err = cryptox.GenerateES256Key()
	case jwtx.AlgorithmEdDSA:
		pemData, err = cryptox.GenerateEd25519Key()
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", s.Algorithm)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %w", err)
	}

	// Create signer from PEM data
	var signer jwtx.Signer
	switch s.Algorithm {
	case jwtx.AlgorithmRS256:
		signer, err = jwtx.NewSignerRS256(kid, pemData)
	case jwtx.AlgorithmES256:
		signer, err = jwtx.NewSignerES256(kid, pemData)
	case jwtx.AlgorithmEdDSA:
		signer, err = jwtx.NewSignerEdDSA(kid, pemData)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to create signer: %w", err)
	}

	now := time.Now()
	gracePeriod := s.GracePeriod
	if gracePeriod <= 0 {
		gracePeriod = 30 * 24 * time.Hour // 30 days default
	}

	var retiredKeys []domain.SigningKey
	var newKey domain.SigningKey

	// Handle persistent mode (with database)
	if s.Store != nil {
		// Encrypt private key for storage
		encryptedKey, err := cryptox.EncryptPrivateKey(pemData)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt private key: %w", err)
		}

		// Create new key record
		newKey = domain.SigningKey{
			ID:                  idx.New().String(),
			Kid:                 kid,
			Algorithm:           s.Algorithm,
			PrivateKeyEncrypted: encryptedKey,
			CreatedAt:           now,
			RetiredAt:           nil, // Active key
			ExpiresAt:           now.Add(gracePeriod),
		}

		// Perform rotation within a transaction
		err = s.Store.WithTx(ctx, func(tx store.Tx) error {
			// Create new key in database
			if err := tx.SigningKeys().CreateSigningKey(ctx, newKey); err != nil {
				return fmt.Errorf("failed to create new signing key: %w", err)
			}

			// Retire existing keys if requested
			if req.RetireExisting {
				activeKeys, err := tx.SigningKeys().ListActiveSigningKeys(ctx)
				if err != nil {
					return fmt.Errorf("failed to list active keys: %w", err)
				}

				for _, key := range activeKeys {
					// Skip the newly created key
					if key.Kid == newKey.Kid {
						continue
					}

					if err := tx.SigningKeys().RetireSigningKey(ctx, key.Kid); err != nil {
						return fmt.Errorf("failed to retire key %s: %w", key.Kid, err)
					}

					// Retire in KeyManager too
					if err := s.KeyManager.RetireSignerByKid(key.Kid); err != nil {
						// Log but don't fail - key might not be in KeyManager
					}

					// Add to retired keys list for response
					key.RetiredAt = &now
					key.ExpiresAt = now.Add(gracePeriod)
					retiredKeys = append(retiredKeys, key)
				}
			}

			return nil
		})

		if err != nil {
			return nil, err
		}
	} else {
		// Ephemeral mode - no database
		newKey = domain.SigningKey{
			Kid:       kid,
			Algorithm: s.Algorithm,
			CreatedAt: now,
		}

		// Retire existing keys if requested
		if req.RetireExisting {
			currentSigners := s.KeyManager.GetSigners()
			for _, currentSigner := range currentSigners {
				if err := s.KeyManager.RetireSignerByKid(currentSigner.KID()); err != nil {
					return nil, fmt.Errorf("failed to retire key %s: %w", currentSigner.KID(), err)
				}

				retiredKeys = append(retiredKeys, domain.SigningKey{
					Kid:       currentSigner.KID(),
					Algorithm: s.Algorithm,
					RetiredAt: &now,
				})
			}
		}
	}

	// Add new signer to KeyManager (both modes)
	if err := s.KeyManager.AddSigner(signer); err != nil {
		return nil, fmt.Errorf("failed to add signer to key manager: %w", err)
	}

	return &RotateKeyResponse{
		NewKey:      newKey,
		RetiredKeys: retiredKeys,
		ActiveKeys:  s.KeyManager.NumSigners(),
	}, nil
}

// ListSigningKeys returns all signing keys with their status.
// In persistent mode, returns keys from database. In ephemeral mode, returns active signers from KeyManager.
func (s *KeyRotationService) ListSigningKeys(ctx context.Context) ([]domain.SigningKey, error) {
	if s.Store != nil {
		// Persistent mode - return from database
		return s.Store.SigningKeys().ListAllSigningKeys(ctx)
	}

	// Ephemeral mode - return from KeyManager
	if s.KeyManager == nil {
		return nil, fmt.Errorf("KeyManager is required")
	}

	signers := s.KeyManager.GetSigners()
	keys := make([]domain.SigningKey, len(signers))
	for i, signer := range signers {
		keys[i] = domain.SigningKey{
			Kid:       signer.KID(),
			Algorithm: s.Algorithm,
			CreatedAt: time.Now(), // We don't track creation time in ephemeral mode
		}
	}

	return keys, nil
}

// RetireKey marks a specific key as retired without generating a new one.
// In persistent mode, the key remains valid for verification during the grace period.
// In ephemeral mode, the key is removed from active signing but remains in KeySet for verification.
func (s *KeyRotationService) RetireKey(ctx context.Context, kid string) error {
	if s.KeyManager == nil {
		return fmt.Errorf("KeyManager is required")
	}

	if s.Store != nil {
		// Persistent mode - retire in database and KeyManager
		key, err := s.Store.SigningKeys().GetSigningKeyByKid(ctx, kid)
		if err != nil {
			return fmt.Errorf("failed to get key: %w", err)
		}

		if key.RetiredAt != nil {
			return fmt.Errorf("key %s is already retired", kid)
		}

		// Retire in database
		if err := s.Store.SigningKeys().RetireSigningKey(ctx, kid); err != nil {
			return fmt.Errorf("failed to retire key: %w", err)
		}

		// Retire in KeyManager
		if err := s.KeyManager.RetireSignerByKid(kid); err != nil {
			// Log but don't fail - key might not be in KeyManager
		}
	} else {
		// Ephemeral mode - retire in KeyManager only
		if err := s.KeyManager.RetireSignerByKid(kid); err != nil {
			return fmt.Errorf("failed to retire key: %w", err)
		}
	}

	return nil
}

// generateRandomKeyID generates a random key identifier using cryptox token generation.
func generateRandomKeyID() (string, error) {
	token, err := cryptox.GenerateToken(cryptox.TokenSize128)
	if err != nil {
		return "", fmt.Errorf("failed to generate random key ID: %w", err)
	}
	return fmt.Sprintf("bartab-%s", token), nil
}
