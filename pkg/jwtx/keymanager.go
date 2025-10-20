package jwtx

import (
	"fmt"
	"math/rand/v2"
	"sync"

	"github.com/aussiebroadwan/bartab/pkg/cryptox"
)

// Supported JWT signing algorithms
const (
	AlgorithmRS256 = "RS256"
	AlgorithmES256 = "ES256"
	AlgorithmEdDSA = "EdDSA"
)

// KeyManager manages JWT signing and verification keys for an instance.
// It provides a unified interface for ephemeral key generation, signing,
// and verification across multiple algorithms.
//
// KeyManager now supports multiple signing keys for improved availability
// and load distribution. Keys are selected randomly for signing operations.
type KeyManager struct {
	// Deprecated: Use GetSigner() instead for multi-key support
	Signer Signer

	Verifier  Verifier
	KeySet    *KeySet
	algorithm string

	// Private fields for multi-key support
	signers []Signer
	mu      sync.RWMutex
}

// KeyManagerOptions configures the KeyManager for a specific use case.
type KeyManagerOptions struct {
	// Algorithm specifies which signing algorithm to use.
	// Supported values: "RS256", "ES256", "EdDSA"
	Algorithm string

	// Issuer is the issuer claim (iss) that will be validated in tokens.
	Issuer string

	// Audience is the list of audience values (aud) that will be validated.
	// Empty slice means no audience validation.
	Audience []string

	// RSABits specifies the RSA key size for RS256 algorithm.
	// Only used when Algorithm is RS256. Defaults to 4096 if not specified.
	// Must be at least 2048.
	RSABits int

	// NumKeys specifies how many signing keys to generate.
	// Multiple keys improve availability and distribute signing load.
	// Defaults to 3 if not specified. Minimum is 1, maximum is 10.
	NumKeys int
}

// NewEphemeralKeyManager creates a new KeyManager with ephemeral keys.
// The keys are generated on the fly and only exist in memory - they are
// never persisted to disk. This means all tokens become invalid when the
// service restarts, which is useful for stateless key rotation.
//
// The manager handles all the wiring between key generation (cryptox),
// signing/verification (jwtx), and the KeySet for JWKS publishing.
//
// By default, creates 3 signing keys with random key IDs for improved
// availability and load distribution. Use opts.NumKeys to customize.
func NewEphemeralKeyManager(opts KeyManagerOptions) (*KeyManager, error) {
	if opts.Issuer == "" {
		return nil, fmt.Errorf("jwtx: Issuer is required")
	}

	// Determine number of keys to generate
	numKeys := opts.NumKeys
	if numKeys <= 0 {
		numKeys = 3 // Default to 3 keys for 0 or negative values
	}
	if numKeys > 10 {
		numKeys = 10 // Cap at 10 keys maximum
	}

	// Create KeySet for JWKS publishing
	keyset := NewKeySet()

	// Generate multiple signing keys
	signers := make([]Signer, 0, numKeys)

	for i := 0; i < numKeys; i++ {
		var keyID string
		var err error

		keyID, err = generateRandomKeyID()
		if err != nil {
			return nil, fmt.Errorf("jwtx: failed to generate key ID: %w", err)
		}

		signer, err := generateSigner(opts.Algorithm, keyID, opts.RSABits)
		if err != nil {
			return nil, fmt.Errorf("jwtx: failed to generate signer %d: %w", i+1, err)
		}

		signers = append(signers, signer)

		// Add signer's public key to KeySet
		if err := keyset.AddSigner(signer); err != nil {
			return nil, fmt.Errorf("jwtx: failed to add signer %d to keyset: %w", i+1, err)
		}
	}

	// Create the appropriate verifier based on algorithm
	var verifier Verifier
	switch opts.Algorithm {
	case AlgorithmRS256:
		verifier = NewCommonRS256(keyset, opts.Issuer, opts.Audience)
	case AlgorithmES256:
		verifier = NewCommonES256(keyset, opts.Issuer, opts.Audience)
	case AlgorithmEdDSA:
		verifier = NewCommonEdDSA(keyset, opts.Issuer, opts.Audience)
	default:
		return nil, fmt.Errorf("jwtx: unsupported algorithm %q (supported: RS256, ES256, EdDSA)", opts.Algorithm)
	}

	// Set first signer as the default for backward compatibility
	var primarySigner Signer
	if len(signers) > 0 {
		primarySigner = signers[0]
	}

	return &KeyManager{
		Signer:    primarySigner, // For backward compatibility
		Verifier:  verifier,
		KeySet:    keyset,
		algorithm: opts.Algorithm,
		signers:   signers,
	}, nil
}

// generateSigner creates a new signer with the specified algorithm and key ID.
// This is a helper function used by NewEphemeralKeyManager to generate multiple keys.
func generateSigner(algorithm, keyID string, rsaBits int) (Signer, error) {
	var pemBytes []byte
	var err error

	switch algorithm {
	case AlgorithmRS256:
		bits := rsaBits
		if bits == 0 {
			bits = 4096 // Default to 4096-bit RSA
		}
		pemBytes, err = cryptox.GenerateRSAKey(bits)
		if err != nil {
			return nil, fmt.Errorf("failed to generate RS256 key: %w", err)
		}
		return NewSignerRS256(keyID, pemBytes)

	case AlgorithmES256:
		pemBytes, err = cryptox.GenerateES256Key()
		if err != nil {
			return nil, fmt.Errorf("failed to generate ES256 key: %w", err)
		}
		return NewSignerES256(keyID, pemBytes)

	case AlgorithmEdDSA:
		pemBytes, err = cryptox.GenerateEd25519Key()
		if err != nil {
			return nil, fmt.Errorf("failed to generate EdDSA key: %w", err)
		}
		return NewSignerEdDSA(keyID, pemBytes)

	default:
		return nil, fmt.Errorf("unsupported algorithm %q", algorithm)
	}
}

// Algorithm returns the signing algorithm being used.
func (km *KeyManager) Algorithm() string {
	return km.algorithm
}

// IsReady returns true if the KeyManager has valid keys loaded.
func (km *KeyManager) IsReady() bool {
	return km.KeySet.IsReady()
}

// GetSigner returns a randomly selected signer from the available signing keys.
// This method distributes signing operations across multiple keys for improved
// load distribution and unpredictability.
//
// For backward compatibility, if only one key exists, it returns that key consistently.
func (km *KeyManager) GetSigner() Signer {
	km.mu.RLock()
	defer km.mu.RUnlock()

	if len(km.signers) == 0 {
		return nil
	}

	if len(km.signers) == 1 {
		return km.signers[0]
	}

	// Random selection for load balancing and unpredictability
	idx := rand.IntN(len(km.signers))
	return km.signers[idx]
}

// NumSigners returns the number of active signing keys.
func (km *KeyManager) NumSigners() int {
	km.mu.RLock()
	defer km.mu.RUnlock()
	return len(km.signers)
}

// AddSigner adds a new signing key to the KeyManager.
// The key is added to both the active signers list (for signing) and the KeySet (for verification).
// This method is thread-safe and can be used for runtime key rotation.
func (km *KeyManager) AddSigner(signer Signer) error {
	if signer == nil {
		return fmt.Errorf("signer cannot be nil")
	}

	km.mu.Lock()
	defer km.mu.Unlock()

	// Add to KeySet for verification
	if err := km.KeySet.AddSigner(signer); err != nil {
		return fmt.Errorf("failed to add signer to keyset: %w", err)
	}

	// Add to active signers list
	km.signers = append(km.signers, signer)

	// Update primary signer if this is the first key
	if len(km.signers) == 1 {
		km.Signer = signer
	}

	return nil
}

// RetireSignerByKid removes a signing key from active signing operations.
// The key remains in the KeySet for token verification (grace period).
// Returns an error if the key is not found or if it's the last active key.
func (km *KeyManager) RetireSignerByKid(kid string) error {
	km.mu.Lock()
	defer km.mu.Unlock()

	// Don't allow retiring the last key
	if len(km.signers) <= 1 {
		return fmt.Errorf("cannot retire the last signing key")
	}

	// Find and remove the signer from the active list
	found := false
	newSigners := make([]Signer, 0, len(km.signers)-1)
	for _, signer := range km.signers {
		if signer.KID() == kid {
			found = true
			// Skip this signer (retire it from active signing)
		} else {
			newSigners = append(newSigners, signer)
		}
	}

	if !found {
		return fmt.Errorf("signer with kid %q not found", kid)
	}

	km.signers = newSigners

	// Update primary signer if needed
	if len(km.signers) > 0 {
		km.Signer = km.signers[0]
	}

	return nil
}

// GetSigners returns a copy of all active signing keys.
// This is useful for listing keys or inspecting the current key state.
func (km *KeyManager) GetSigners() []Signer {
	km.mu.RLock()
	defer km.mu.RUnlock()

	signers := make([]Signer, len(km.signers))
	copy(signers, km.signers)
	return signers
}

// generateRandomKeyID creates a random key identifier using cryptographic entropy.
// Format: "bartab-{random-token}" where random-token is a 128-bit secure token.
func generateRandomKeyID() (string, error) {
	token, err := cryptox.GenerateToken(cryptox.TokenSize128)
	if err != nil {
		return "", fmt.Errorf("failed to generate random key ID: %w", err)
	}
	return fmt.Sprintf("bartab-%s", token), nil
}
