package cryptox_test

import (
	"os"
	"testing"

	"github.com/aussiebroadwan/bartab/pkg/cryptox"
	"github.com/stretchr/testify/require"
)

func TestEncryptDecryptPrivateKey(t *testing.T) {
	// Set a test master key
	os.Setenv("AUTH_MASTER_KEY", "test-master-key-for-encryption-12345")
	t.Cleanup(func() {
		os.Unsetenv("AUTH_MASTER_KEY")
		cryptox.ResetMasterKeyForTesting()
	})

	testPEM := []byte(`-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgTest1234567890abcd
efghijklmnopqrstuv==
-----END PRIVATE KEY-----`)

	// Encrypt
	encrypted, err := cryptox.EncryptPrivateKey(testPEM)
	require.NoError(t, err)
	require.NotEmpty(t, encrypted)
	require.NotEqual(t, testPEM, encrypted, "encrypted data should differ from plaintext")

	// Decrypt
	decrypted, err := cryptox.DecryptPrivateKey(encrypted)
	require.NoError(t, err)
	require.Equal(t, testPEM, decrypted, "decrypted data should match original")
}

func TestEncryptDecryptMultipleTimes(t *testing.T) {
	os.Setenv("AUTH_MASTER_KEY", "test-master-key-multiple-times-xyz")
	t.Cleanup(func() {
		os.Unsetenv("AUTH_MASTER_KEY")
		cryptox.ResetMasterKeyForTesting()
	})

	testData := []byte("sensitive-private-key-data-12345")

	// Encrypt multiple times - should produce different ciphertexts due to random nonce
	encrypted1, err := cryptox.EncryptPrivateKey(testData)
	require.NoError(t, err)

	encrypted2, err := cryptox.EncryptPrivateKey(testData)
	require.NoError(t, err)

	require.NotEqual(t, encrypted1, encrypted2, "multiple encryptions should produce different ciphertexts")

	// But both should decrypt to the same plaintext
	decrypted1, err := cryptox.DecryptPrivateKey(encrypted1)
	require.NoError(t, err)
	require.Equal(t, testData, decrypted1)

	decrypted2, err := cryptox.DecryptPrivateKey(encrypted2)
	require.NoError(t, err)
	require.Equal(t, testData, decrypted2)
}

func TestDecryptInvalidData(t *testing.T) {
	os.Setenv("AUTH_MASTER_KEY", "test-master-key-invalid-data")
	t.Cleanup(func() {
		os.Unsetenv("AUTH_MASTER_KEY")
		cryptox.ResetMasterKeyForTesting()
	})

	// Try to decrypt garbage data
	_, err := cryptox.DecryptPrivateKey([]byte("invalid-encrypted-data"))
	require.Error(t, err, "decrypting invalid data should fail")
}

func TestDecryptTamperedData(t *testing.T) {
	os.Setenv("AUTH_MASTER_KEY", "test-master-key-tampered")
	t.Cleanup(func() {
		os.Unsetenv("AUTH_MASTER_KEY")
		cryptox.ResetMasterKeyForTesting()
	})

	testData := []byte("original-data")

	encrypted, err := cryptox.EncryptPrivateKey(testData)
	require.NoError(t, err)

	// Tamper with the encrypted data
	tampered := make([]byte, len(encrypted))
	copy(tampered, encrypted)
	tampered[len(tampered)-1] ^= 0xFF // Flip bits in last byte

	// Decryption should fail due to authentication tag mismatch
	_, err = cryptox.DecryptPrivateKey(tampered)
	require.Error(t, err, "decrypting tampered data should fail")
}

func TestDecryptTooShort(t *testing.T) {
	os.Setenv("AUTH_MASTER_KEY", "test-master-key-short")
	t.Cleanup(func() {
		os.Unsetenv("AUTH_MASTER_KEY")
		cryptox.ResetMasterKeyForTesting()
	})

	// Data too short to contain nonce
	_, err := cryptox.DecryptPrivateKey([]byte("short"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "too short")
}

func TestMasterKeyFromFile(t *testing.T) {
	// Create temporary key file
	tmpfile, err := os.CreateTemp("", "masterkey-*.key")
	require.NoError(t, err)
	defer os.Remove(tmpfile.Name())

	_, err = tmpfile.Write([]byte("file-based-master-key-content-xyz"))
	require.NoError(t, err)
	tmpfile.Close()

	// Reset and configure to use file
	cryptox.ResetMasterKeyForTesting()
	cryptox.SetMasterKeyPath(tmpfile.Name())
	t.Cleanup(func() {
		cryptox.ResetMasterKeyForTesting()
		cryptox.SetMasterKeyPath("")
	})

	testData := []byte("test-data-with-file-key")

	// Encrypt with file-based key
	encrypted, err := cryptox.EncryptPrivateKey(testData)
	require.NoError(t, err)

	// Decrypt with file-based key
	decrypted, err := cryptox.DecryptPrivateKey(encrypted)
	require.NoError(t, err)
	require.Equal(t, testData, decrypted)
}

func TestLargePrivateKey(t *testing.T) {
	os.Setenv("AUTH_MASTER_KEY", "test-master-key-large")
	t.Cleanup(func() {
		os.Unsetenv("AUTH_MASTER_KEY")
		cryptox.ResetMasterKeyForTesting()
	})

	// Generate a 4096-bit RSA private key PEM (large)
	largeKey, err := cryptox.GenerateRSAKey(4096)
	require.NoError(t, err)

	// Encrypt large key
	encrypted, err := cryptox.EncryptPrivateKey(largeKey)
	require.NoError(t, err)

	// Decrypt large key
	decrypted, err := cryptox.DecryptPrivateKey(encrypted)
	require.NoError(t, err)
	require.Equal(t, largeKey, decrypted)
}
