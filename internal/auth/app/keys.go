package app

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/aussiebroadwan/bartab/internal/auth/store"
	"github.com/aussiebroadwan/bartab/pkg/cryptox"
	"github.com/aussiebroadwan/bartab/pkg/jwtx"
)

// InitAuthKeys creates a new KeyManager with the configured algorithm and storage mode.
//
// Storage modes:
//   - "ephemeral": Keys are generated on startup and stored only in memory.
//     All existing tokens become invalid when the service restarts.
//   - "persistent": Keys are stored in the database with encryption.
//     Tokens survive service restarts. Supports key rotation with grace period.
//
// Supported algorithms: RS256, ES256, EdDSA
//
// By default, generates 3 signing keys with random identifiers for improved
// availability and load distribution. Use AUTH_NUM_KEYS to customize.
func InitAuthKeys(ctx context.Context, cfg Config, db store.Store, logger *slog.Logger) (*jwtx.KeyManager, error) {
	// Configure master key path if provided (for persistent mode)
	if cfg.MasterKeyPath != "" {
		cryptox.SetMasterKeyPath(cfg.MasterKeyPath)
		logger.Info("master key path configured", "path", cfg.MasterKeyPath)
	}

	var keyManager *jwtx.KeyManager
	var err error

	switch cfg.KeyStorageMode {
	case "persistent":
		// Create adapter to bridge store and jwtx interfaces
		keyStore := store.NewKeyStoreAdapter(db)

		logger.Info("initializing persistent key manager",
			"algorithm", cfg.Algorithm,
			"num_keys", cfg.NumKeys,
			"grace_period", cfg.KeyGracePeriod,
		)

		keyManager, err = jwtx.NewPersistentKeyManager(ctx, jwtx.PersistentKeyManagerOptions{
			Store:       keyStore,
			Algorithm:   cfg.Algorithm,
			Issuer:      cfg.Issuer,
			Audience:    nil, // Empty audience list means no audience validation (tokens have dynamic audience = client ID)
			RSABits:     cfg.RSABits,
			NumKeys:     cfg.NumKeys,
			GracePeriod: cfg.KeyGracePeriod,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to initialize persistent key manager: %w", err)
		}

		numKeys := keyManager.NumSigners()
		logger.Info("persistent signing keys loaded/generated",
			"algorithm", keyManager.Algorithm(),
			"num_keys", numKeys,
			"issuer", cfg.Issuer,
			"grace_period", cfg.KeyGracePeriod,
		)

		logger.Info("persistent key mode enabled - tokens will survive restarts")

	case "ephemeral":
		fallthrough
	default:
		logger.Info("initializing ephemeral key manager",
			"algorithm", cfg.Algorithm,
			"num_keys", cfg.NumKeys,
		)

		keyManager, err = jwtx.NewEphemeralKeyManager(jwtx.KeyManagerOptions{
			Algorithm: cfg.Algorithm,
			Issuer:    cfg.Issuer,
			Audience:  nil, // Empty audience list means no audience validation (tokens have dynamic audience = client ID)
			RSABits:   cfg.RSABits,
			NumKeys:   cfg.NumKeys,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to initialize ephemeral key manager: %w", err)
		}

		numKeys := keyManager.NumSigners()
		logger.Info("generated ephemeral signing keys",
			"algorithm", keyManager.Algorithm(),
			"num_keys", numKeys,
			"issuer", cfg.Issuer,
		)

		logger.Warn("all existing tokens are now invalid due to key rotation on startup")
	}

	return keyManager, nil
}
