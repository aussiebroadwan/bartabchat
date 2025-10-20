package jwtx

import (
	"context"
	"fmt"
	"time"

	"github.com/aussiebroadwan/bartab/pkg/cryptox"
)

// SigningKeyRecord represents a signing key stored in the database.
// This interface avoids importing the domain package, preventing circular dependencies.
type SigningKeyRecord struct {
	ID                  string
	Kid                 string
	Algorithm           string
	PrivateKeyEncrypted []byte
	CreatedAt           time.Time
	RetiredAt           *time.Time
	ExpiresAt           time.Time
}

// KeyStore defines the minimal interface needed for persistent key management.
// This allows the jwtx package to work with keys without depending on the store package.
type KeyStore interface {
	// ListAllSigningKeys returns all signing keys (including retired and expired)
	// for verification during grace period.
	ListAllSigningKeys(ctx context.Context) ([]SigningKeyRecord, error)

	// ListActiveSigningKeys returns only active (non-retired, non-expired) keys
	// for signing operations.
	ListActiveSigningKeys(ctx context.Context) ([]SigningKeyRecord, error)

	// CreateSigningKey stores a new signing key with encrypted private key material.
	CreateSigningKey(ctx context.Context, key SigningKeyRecord) error
}

// PersistentKeyManagerOptions configures a KeyManager with persistent key storage.
type PersistentKeyManagerOptions struct {
	// Store provides access to the signing keys database.
	Store KeyStore

	// Algorithm specifies which signing algorithm to use for NEW keys.
	// Loaded keys will use their stored algorithm.
	Algorithm string

	// Issuer is the issuer claim (iss) that will be validated in tokens.
	Issuer string

	// Audience is the list of audience values (aud) that will be validated.
	// Empty slice means no audience validation.
	Audience []string

	// RSABits specifies the RSA key size for RS256 algorithm when generating new keys.
	// Only used when Algorithm is RS256. Defaults to 4096 if not specified.
	RSABits int

	// NumKeys specifies the target number of active signing keys.
	// If fewer active keys exist in the database, new ones will be generated.
	// Defaults to 3 if not specified.
	NumKeys int

	// GracePeriod is how long retired keys remain valid for verification.
	// Keys are marked expired after (retired_at + GracePeriod).
	// Defaults to 30 days if not specified.
	GracePeriod time.Duration
}

// NewPersistentKeyManager creates a KeyManager that loads keys from a database.
// Unlike ephemeral keys, these keys survive service restarts and support
// gradual rotation with a grace period for token verification.
//
// On initialization, it will:
// 1. Load all keys from the database (for verification)
// 2. Load active keys only (for signing)
// 3. Generate new keys if needed to reach NumKeys target
// 4. Add all keys to JWKS for public key distribution
func NewPersistentKeyManager(ctx context.Context, opts PersistentKeyManagerOptions) (*KeyManager, error) {
	if opts.Store == nil {
		return nil, fmt.Errorf("jwtx: Store is required for persistent key manager")
	}
	if opts.Issuer == "" {
		return nil, fmt.Errorf("jwtx: Issuer is required")
	}

	// Set defaults
	if opts.NumKeys <= 0 {
		opts.NumKeys = 3
	}
	if opts.NumKeys > 10 {
		opts.NumKeys = 10
	}
	if opts.GracePeriod <= 0 {
		opts.GracePeriod = 30 * 24 * time.Hour // 30 days default
	}

	// Load all keys from database (including retired) for verification
	allKeys, err := opts.Store.ListAllSigningKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("jwtx: failed to load keys from database: %w", err)
	}

	// Load active keys for signing
	activeKeys, err := opts.Store.ListActiveSigningKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("jwtx: failed to load active keys: %w", err)
	}

	// Create KeySet for JWKS publishing - add ALL keys for verification
	keyset := NewKeySet()

	// Decrypt and create signers for all keys (for verification)
	for _, keyRecord := range allKeys {
		// Decrypt private key
		pemData, err := cryptox.DecryptPrivateKey(keyRecord.PrivateKeyEncrypted)
		if err != nil {
			return nil, fmt.Errorf("jwtx: failed to decrypt key %s: %w", keyRecord.Kid, err)
		}

		// Create signer based on algorithm
		signer, err := createSignerFromPEM(keyRecord.Algorithm, keyRecord.Kid, pemData)
		if err != nil {
			return nil, fmt.Errorf("jwtx: failed to create signer for key %s: %w", keyRecord.Kid, err)
		}

		// Add to KeySet for verification
		if err := keyset.AddSigner(signer); err != nil {
			return nil, fmt.Errorf("jwtx: failed to add key %s to keyset: %w", keyRecord.Kid, err)
		}
	}

	// Create list of active signers only (for signing operations)
	activeSigners := make([]Signer, 0, len(activeKeys))
	for _, keyRecord := range activeKeys {
		// Decrypt private key
		pemData, err := cryptox.DecryptPrivateKey(keyRecord.PrivateKeyEncrypted)
		if err != nil {
			return nil, fmt.Errorf("jwtx: failed to decrypt active key %s: %w", keyRecord.Kid, err)
		}

		// Create signer
		signer, err := createSignerFromPEM(keyRecord.Algorithm, keyRecord.Kid, pemData)
		if err != nil {
			return nil, fmt.Errorf("jwtx: failed to create active signer %s: %w", keyRecord.Kid, err)
		}

		activeSigners = append(activeSigners, signer)
	}

	// Generate new keys if we don't have enough active keys
	now := time.Now()
	for len(activeSigners) < opts.NumKeys {
		kid, err := generateRandomKeyID()
		if err != nil {
			return nil, fmt.Errorf("jwtx: failed to generate key ID: %w", err)
		}

		// Generate new key
		pemData, signer, err := generateNewKeyAndSigner(opts.Algorithm, kid, opts.RSABits)
		if err != nil {
			return nil, fmt.Errorf("jwtx: failed to generate new key: %w", err)
		}

		// Encrypt private key for storage
		encryptedKey, err := cryptox.EncryptPrivateKey(pemData)
		if err != nil {
			return nil, fmt.Errorf("jwtx: failed to encrypt new key: %w", err)
		}

		// Store in database
		keyRecord := SigningKeyRecord{
			ID:                  generateKeyRecordID(), // Generate ULID
			Kid:                 kid,
			Algorithm:           opts.Algorithm,
			PrivateKeyEncrypted: encryptedKey,
			CreatedAt:           now,
			RetiredAt:           nil,                       // Active key
			ExpiresAt:           now.Add(opts.GracePeriod), // Will be extended when retired
		}

		if err := opts.Store.CreateSigningKey(ctx, keyRecord); err != nil {
			return nil, fmt.Errorf("jwtx: failed to store new key: %w", err)
		}

		// Add to active signers and keyset
		activeSigners = append(activeSigners, signer)
		if err := keyset.AddSigner(signer); err != nil {
			return nil, fmt.Errorf("jwtx: failed to add new key to keyset: %w", err)
		}
	}

	// Create verifier based on algorithm
	var verifier Verifier
	switch opts.Algorithm {
	case AlgorithmRS256:
		verifier = NewCommonRS256(keyset, opts.Issuer, opts.Audience)
	case AlgorithmES256:
		verifier = NewCommonES256(keyset, opts.Issuer, opts.Audience)
	case AlgorithmEdDSA:
		verifier = NewCommonEdDSA(keyset, opts.Issuer, opts.Audience)
	default:
		return nil, fmt.Errorf("jwtx: unsupported algorithm %q", opts.Algorithm)
	}

	// Set first active signer as primary for backward compatibility
	var primarySigner Signer
	if len(activeSigners) > 0 {
		primarySigner = activeSigners[0]
	}

	return &KeyManager{
		Signer:    primarySigner,
		Verifier:  verifier,
		KeySet:    keyset,
		algorithm: opts.Algorithm,
		signers:   activeSigners,
	}, nil
}

// createSignerFromPEM creates a signer from PEM-encoded private key data.
func createSignerFromPEM(algorithm, kid string, pemData []byte) (Signer, error) {
	switch algorithm {
	case AlgorithmRS256:
		return NewSignerRS256(kid, pemData)
	case AlgorithmES256:
		return NewSignerES256(kid, pemData)
	case AlgorithmEdDSA:
		return NewSignerEdDSA(kid, pemData)
	default:
		return nil, fmt.Errorf("unsupported algorithm %q", algorithm)
	}
}

// generateNewKeyAndSigner generates a new key pair and returns both the PEM data and signer.
func generateNewKeyAndSigner(algorithm, kid string, rsaBits int) ([]byte, Signer, error) {
	var pemData []byte
	var err error

	switch algorithm {
	case AlgorithmRS256:
		if rsaBits == 0 {
			rsaBits = 4096
		}
		pemData, err = cryptox.GenerateRSAKey(rsaBits)
	case AlgorithmES256:
		pemData, err = cryptox.GenerateES256Key()
	case AlgorithmEdDSA:
		pemData, err = cryptox.GenerateEd25519Key()
	default:
		return nil, nil, fmt.Errorf("unsupported algorithm %q", algorithm)
	}

	if err != nil {
		return nil, nil, err
	}

	signer, err := createSignerFromPEM(algorithm, kid, pemData)
	if err != nil {
		return nil, nil, err
	}

	return pemData, signer, nil
}

// generateKeyRecordID generates a ULID for a key record.
// This is a temporary implementation - in production you'd use the idx package.
func generateKeyRecordID() string {
	// Simple timestamp-based ID for now
	// In production, use: idx.New().String()
	return fmt.Sprintf("key-%d", time.Now().UnixNano())
}
