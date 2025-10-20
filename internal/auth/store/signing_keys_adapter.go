package store

import (
	"context"

	"github.com/aussiebroadwan/bartab/internal/auth/domain"
	"github.com/aussiebroadwan/bartab/pkg/jwtx"
)

// KeyStoreAdapter adapts the store.Store interface to the jwtx.KeyStore interface.
// This allows the jwtx package to work with signing keys without depending on the
// domain package directly, preventing circular dependencies.
type KeyStoreAdapter struct {
	store Store
}

// NewKeyStoreAdapter creates a new adapter that implements jwtx.KeyStore using a store.Store.
func NewKeyStoreAdapter(store Store) *KeyStoreAdapter {
	return &KeyStoreAdapter{store: store}
}

// ListAllSigningKeys returns all signing keys (including retired and expired)
// for verification during grace period.
func (a *KeyStoreAdapter) ListAllSigningKeys(ctx context.Context) ([]jwtx.SigningKeyRecord, error) {
	keys, err := a.store.SigningKeys().ListAllSigningKeys(ctx)
	if err != nil {
		return nil, err
	}

	return domainKeysToJWTXRecords(keys), nil
}

// ListActiveSigningKeys returns only active (non-retired, non-expired) keys
// for signing operations.
func (a *KeyStoreAdapter) ListActiveSigningKeys(ctx context.Context) ([]jwtx.SigningKeyRecord, error) {
	keys, err := a.store.SigningKeys().ListActiveSigningKeys(ctx)
	if err != nil {
		return nil, err
	}

	return domainKeysToJWTXRecords(keys), nil
}

// CreateSigningKey stores a new signing key with encrypted private key material.
func (a *KeyStoreAdapter) CreateSigningKey(ctx context.Context, key jwtx.SigningKeyRecord) error {
	domainKey := jwtxRecordToDomain(key)
	return a.store.SigningKeys().CreateSigningKey(ctx, domainKey)
}

// domainKeysToJWTXRecords converts a slice of domain.SigningKey to jwtx.SigningKeyRecord.
func domainKeysToJWTXRecords(keys []domain.SigningKey) []jwtx.SigningKeyRecord {
	records := make([]jwtx.SigningKeyRecord, len(keys))
	for i, key := range keys {
		records[i] = jwtx.SigningKeyRecord{
			ID:                  key.ID,
			Kid:                 key.Kid,
			Algorithm:           key.Algorithm,
			PrivateKeyEncrypted: key.PrivateKeyEncrypted,
			CreatedAt:           key.CreatedAt,
			RetiredAt:           key.RetiredAt,
			ExpiresAt:           key.ExpiresAt,
		}
	}
	return records
}

// jwtxRecordToDomain converts a jwtx.SigningKeyRecord to domain.SigningKey.
func jwtxRecordToDomain(record jwtx.SigningKeyRecord) domain.SigningKey {
	return domain.SigningKey{
		ID:                  record.ID,
		Kid:                 record.Kid,
		Algorithm:           record.Algorithm,
		PrivateKeyEncrypted: record.PrivateKeyEncrypted,
		CreatedAt:           record.CreatedAt,
		RetiredAt:           record.RetiredAt,
		ExpiresAt:           record.ExpiresAt,
	}
}
