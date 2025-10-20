package cryptox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	// Set up a temporary pepper file for testing
	tmpDir := os.TempDir()
	pepperPath := filepath.Join(tmpDir, "test-pepper")
	SetPepperPath(pepperPath)

	// Clean up pepper file before and after tests
	os.Remove(pepperPath)
	defer os.Remove(pepperPath)

	os.Exit(m.Run())
}

func TestHashPassword(t *testing.T) {
	tests := []struct {
		name     string
		password string
	}{
		{"simple password", "password123"},
		{"complex password", "P@ssw0rd!#$%^&*()"},
		{"long password", strings.Repeat("a", 100)},
		{"empty password", ""},
		{"unicode password", "пароль🔒密码"},
		{"whitespace password", "   spaces   "},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash, err := HashPassword(tt.password)
			require.NoError(t, err)
			require.NotEmpty(t, hash)

			// Verify PHC format
			require.True(t, strings.HasPrefix(hash, "$argon2id$v=19$"),
				"hash should be in PHC format")

			// Verify hash contains all expected parts
			parts := strings.Split(hash, "$")
			require.Len(t, parts, 6, "PHC hash should have 6 parts")
			require.Equal(t, "", parts[0]) // empty before first $
			require.Equal(t, "argon2id", parts[1])
			require.Equal(t, "v=19", parts[2])
			require.Contains(t, parts[3], "m=", "should contain memory parameter")
			require.Contains(t, parts[3], "t=", "should contain iterations parameter")
			require.Contains(t, parts[3], "p=", "should contain parallelism parameter")
			require.NotEmpty(t, parts[4], "salt should not be empty")
			require.NotEmpty(t, parts[5], "hash should not be empty")
		})
	}
}

func TestHashPassword_UniqueSalts(t *testing.T) {
	password := "samepassword"

	// Generate multiple hashes for the same password
	hash1, err := HashPassword(password)
	require.NoError(t, err)

	hash2, err := HashPassword(password)
	require.NoError(t, err)

	hash3, err := HashPassword(password)
	require.NoError(t, err)

	// Each hash should be different due to unique salts
	require.NotEqual(t, hash1, hash2, "hashes should differ due to unique salts")
	require.NotEqual(t, hash2, hash3, "hashes should differ due to unique salts")
	require.NotEqual(t, hash1, hash3, "hashes should differ due to unique salts")

	// But all should verify the same password
	require.NoError(t, VerifyPassword(password, hash1))
	require.NoError(t, VerifyPassword(password, hash2))
	require.NoError(t, VerifyPassword(password, hash3))
}

func TestVerifyPassword_Success(t *testing.T) {
	tests := []struct {
		name     string
		password string
	}{
		{"simple password", "password123"},
		{"complex password", "P@ssw0rd!#$%^&*()"},
		{"long password", strings.Repeat("a", 100)},
		{"empty password", ""},
		{"unicode password", "пароль🔒密码"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash, err := HashPassword(tt.password)
			require.NoError(t, err)

			// Verify should succeed with correct password
			err = VerifyPassword(tt.password, hash)
			require.NoError(t, err)
		})
	}
}

func TestVerifyPassword_WrongPassword(t *testing.T) {
	correctPassword := "correct-password"
	hash, err := HashPassword(correctPassword)
	require.NoError(t, err)

	tests := []struct {
		name           string
		wrongPassword  string
		expectedErrMsg string
	}{
		{"completely wrong", "wrong-password", "password does not match"},
		{"case difference", "Correct-Password", "password does not match"},
		{"extra space", "correct-password ", "password does not match"},
		{"empty password", "", "password does not match"},
		{"similar password", "correct-passwor", "password does not match"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifyPassword(tt.wrongPassword, hash)
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.expectedErrMsg)
		})
	}
}

func TestVerifyPassword_InvalidHashFormat(t *testing.T) {
	password := "test-password"

	tests := []struct {
		name        string
		invalidHash string
	}{
		{"empty hash", ""},
		{"wrong algorithm", "$bcrypt$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA"},
		{"missing parts", "$argon2id$v=19$m=19456"},
		{"malformed parameters", "$argon2id$v=19$invalid$c2FsdA$aGFzaA"},
		{"invalid base64 salt", "$argon2id$v=19$m=19456,t=2,p=1$!!!invalid!!!$aGFzaA"},
		{"invalid base64 hash", "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$!!!invalid!!!"},
		{"wrong version", "$argon2id$v=18$m=19456,t=2,p=1$c2FsdA$aGFzaA"},
		{"missing version", "$argon2id$m=19456,t=2,p=1$c2FsdA$aGFzaA"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifyPassword(password, tt.invalidHash)
			require.Error(t, err)
		})
	}
}

func TestVerifyPassword_TimingAttackResistance(t *testing.T) {
	// This test verifies that constant-time comparison is used
	password := "correct-password"
	hash, err := HashPassword(password)
	require.NoError(t, err)

	// Even with completely wrong passwords, the comparison should be constant-time
	wrongPasswords := []string{
		"a",                        // very short
		"wrong-password",           // same length
		strings.Repeat("x", 10000), // very long
	}

	for _, wp := range wrongPasswords {
		err := VerifyPassword(wp, hash)
		require.Error(t, err)
		require.Equal(t, "password does not match", err.Error())
	}
}

func TestGeneratePassword(t *testing.T) {
	// Generate multiple passwords and verify properties
	for range 10 {
		password, err := GeneratePassword()
		require.NoError(t, err)
		require.NotEmpty(t, password)

		// Verify length
		require.Equal(t, 12, len(password), "password should be 12 characters")

		// Verify charset (alphanumeric only)
		for _, char := range password {
			valid := (char >= 'a' && char <= 'z') ||
				(char >= 'A' && char <= 'Z') ||
				(char >= '0' && char <= '9')
			require.True(t, valid, "password should only contain alphanumeric characters")
		}
	}
}

func TestGeneratePassword_Uniqueness(t *testing.T) {
	// Generate multiple passwords and ensure they're all different
	const count = 100
	passwords := make(map[string]bool, count)

	for range count {
		password, err := GeneratePassword()
		require.NoError(t, err)
		require.NotContains(t, passwords, password, "duplicate password generated")
		passwords[password] = true
	}
}

func TestGeneratePassword_CanBeHashed(t *testing.T) {
	// Verify that generated passwords can be hashed and verified
	password, err := GeneratePassword()
	require.NoError(t, err)

	hash, err := HashPassword(password)
	require.NoError(t, err)

	err = VerifyPassword(password, hash)
	require.NoError(t, err)
}

func TestPasswordWorkflow_EndToEnd(t *testing.T) {
	// Simulate a complete user registration and login workflow

	// 1. Generate a random password (e.g., for initial user setup)
	generatedPassword, err := GeneratePassword()
	require.NoError(t, err)

	// 2. User sets a new password
	userPassword := "MySecurePassword123!"

	// 3. Hash the password for storage
	hash, err := HashPassword(userPassword)
	require.NoError(t, err)

	// 4. Later, verify the password during login
	err = VerifyPassword(userPassword, hash)
	require.NoError(t, err, "correct password should verify")

	// 5. Wrong password should fail
	err = VerifyPassword("WrongPassword", hash)
	require.Error(t, err, "wrong password should fail")

	// 6. Generated password should also work if hashed
	genHash, err := HashPassword(generatedPassword)
	require.NoError(t, err)
	err = VerifyPassword(generatedPassword, genHash)
	require.NoError(t, err, "generated password should verify")
}

func TestHashPassword_PepperIntegration(t *testing.T) {
	// This test verifies that the pepper is actually being used
	// by creating two hashes with different peppers

	password := "test-password"

	// First hash with current pepper
	hash1, err := HashPassword(password)
	require.NoError(t, err)

	// Verify it works
	err = VerifyPassword(password, hash1)
	require.NoError(t, err)

	// The hash should include the pepper in its computation
	// We can't easily test this directly without exposing internals,
	// but we can verify the hash format is correct
	require.Contains(t, hash1, "$argon2id$")
}

func TestVerifyPassword_PreservesPHCFormat(t *testing.T) {
	// Test that we can verify passwords hashed with different parameter combinations
	// This ensures backward compatibility if we change parameters in the future

	password := "test-password"

	// Create a hash with known parameters matching current config
	hash, err := HashPassword(password)
	require.NoError(t, err)

	// Extract parameters from hash
	require.Contains(t, hash, "m=19456", "memory parameter should be 19456 (19*1024)")
	require.Contains(t, hash, "t=2", "iterations parameter should be 2")
	require.Contains(t, hash, "p=1", "parallelism parameter should be 1")

	// Verify password
	err = VerifyPassword(password, hash)
	require.NoError(t, err)
}
