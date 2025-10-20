package cryptox

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"

	"golang.org/x/crypto/argon2"
)

// HashPassword generates a PHC-format Argon2id hash string including salt and parameters.
func HashPassword(password string) (string, error) {
	salt := make([]byte, saltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	hash := argon2.IDKey(
		[]byte(password+GetPepper()),
		salt,
		iterations,
		memory,
		parallelism,
		keyLength,
	)
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	// Return PHC-style encoded string
	return fmt.Sprintf(
		"$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		memory,
		iterations,
		parallelism,
		b64Salt,
		b64Hash,
	), nil
}

// VerifyPassword compares a plaintext password against a PHC-style Argon2id hash.
func VerifyPassword(password, encodedHash string) error {
	// Parse PHC format: $argon2id$v=19$m=X,t=Y,p=Z$salt$hash
	// Split by $ to extract components
	parts := make([]string, 0, 6)
	start := 0
	for i := range len(encodedHash) {
		if encodedHash[i] == '$' {
			parts = append(parts, encodedHash[start:i])
			start = i + 1
		}
	}
	parts = append(parts, encodedHash[start:]) // Add last part

	// Validate structure: ["", "argon2id", "v=19", "m=X,t=Y,p=Z", "salt", "hash"]
	if len(parts) != 6 {
		return errors.New("invalid hash format: expected 6 parts")
	}
	if parts[1] != "argon2id" {
		return errors.New("invalid hash format: not argon2id")
	}
	if parts[2] != "v=19" {
		return errors.New("invalid hash format: wrong version")
	}

	// Parse parameters from parts[3]
	var mem, iters uint32
	var par uint8
	_, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &mem, &iters, &par)
	if err != nil {
		return fmt.Errorf("invalid hash format: failed to parse parameters: %w", err)
	}

	// Decode salt and hash
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return fmt.Errorf("invalid hash format: failed to decode salt: %w", err)
	}
	expectedHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return fmt.Errorf("invalid hash format: failed to decode hash: %w", err)
	}

	computed := argon2.IDKey(
		[]byte(password+GetPepper()),
		salt,
		iters,
		mem,
		par,
		uint32(len(expectedHash)), // #nosec G115 - If this overflows we have bigger problems
	)

	if subtle.ConstantTimeCompare(computed, expectedHash) == 1 {
		return nil
	}
	return errors.New("password does not match")
}

func GeneratePassword() (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	const length = 12
	password := make([]byte, length)
	for i := range password {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "", fmt.Errorf("failed to generate random password: %w", err)
		}
		password[i] = charset[n.Int64()]
	}
	return string(password), nil
}
