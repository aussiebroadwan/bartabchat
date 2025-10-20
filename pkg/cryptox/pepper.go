package cryptox

import (
	"crypto/rand"
	"encoding/base64"
	"log/slog"
	"os"
	"path/filepath"
)

// Configuration for Argon2id hashing.
const (
	memory      = 19 * 1024 // Memory usage in KiB (19 MiB)
	iterations  = 2         // Iteration count
	parallelism = 1         // Number of threads
	keyLength   = 32        // Length of the generated hash
	saltLength  = 16        // Length of the salt
)

var (
	// Pepper is dynamically loaded from a file or generated at runtime.
	pepper     string
	pepperFile string
)

func SetPepperPath(file string) {
	pepperFile = file
}

func GetPepper() string {
	if pepper != "" {
		return pepper
	}

	var err error
	pepper, err = loadOrGeneratePepper()
	if err != nil {
		slog.Error("failed to load or generate pepper", slog.Any("err", err))
		os.Exit(1)
	}

	return pepper
}

// loadOrGeneratePepper loads the pepper from a file or generates one if not found.
func loadOrGeneratePepper() (string, error) {
	pepperFile = filepath.Clean(pepperFile)
	pepperDir := filepath.Dir(pepperFile)
	if err := os.MkdirAll(pepperDir, 0750); err != nil {
		return "", err
	}

	if _, err := os.Stat(pepperFile); os.IsNotExist(err) {
		// Generate a new pepper and save it to the file
		pepperBytes := make([]byte, keyLength)
		if _, err := rand.Read(pepperBytes); err != nil {
			return "", err
		}
		pepper := base64.RawURLEncoding.EncodeToString(pepperBytes)

		// Write the pepper to the file
		if err := os.WriteFile(pepperFile, []byte(pepper), 0600); err != nil {
			return "", err
		}
		return pepper, nil
	}

	// Load existing pepper from file
	pepperBytes, err := os.ReadFile(pepperFile)
	if err != nil {
		return "", err
	}

	return string(pepperBytes), nil
}

func ReloadPepper() error {
	// Load or generate pepper to refresh it if it has been restored
	var err error
	pepper, err = loadOrGeneratePepper()
	if err != nil {
		slog.Error("failed to load or generate pepper", slog.Any("err", err))
		return err
	}
	return nil
}
