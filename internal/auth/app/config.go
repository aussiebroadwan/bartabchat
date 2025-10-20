package app

import (
	"os"
	"strconv"
	"time"
)

type Config struct {
	Issuer         string // Required: issuer claim for tokens
	BootstrapToken string // Optional: token required to perform bootstrap

	Algorithm            string        // Optional: JWT signing algorithm (RS256, ES256, EdDSA) (default: EdDSA)
	RSABits              int           // Optional: RSA key size for RS256 (default: 4096)
	NumKeys              int           // Optional: number of signing keys to generate (default: 3, min: 1, max: 10)
	KeyStorageMode       string        // Optional: key storage mode (ephemeral, persistent) (default: ephemeral)
	KeyGracePeriod       time.Duration // Optional: grace period for retired keys (default: 30 days)
	MasterKeyPath        string        // Optional: path to master encryption key file (for persistent keys)
	DatabaseFile         string        // Optional: path to SQLite database file (default: ./auth.db)
	PepperFile           string        // Optional: path to file containing pepper for password hashing (default: ./pepper)
	Env                  string        // Environment (dev, staging, prod) (default: dev)
	LogLevel             string        // Log level (debug, info, warn, error) (default: info)
	LogFormat            string        // Log format (json, text) (default: json)
	Port                 int           // HTTP server port (default: 8080)
	ShutdownGracePeriod  time.Duration // Graceful shutdown timeout (default: 10s)
	HousekeepingInterval time.Duration // Housekeeping interval (default: 1h)
}

func LoadConfig() Config {
	cfg := Config{
		Issuer:         os.Getenv("AUTH_ISSUER"),
		Algorithm:      getEnvOrDefault("AUTH_ALGORITHM", "EdDSA"),                        // Default to EdDSA
		KeyStorageMode: getEnvOrDefault("AUTH_KEY_STORAGE_MODE", "ephemeral"),             // Default to ephemeral
		KeyGracePeriod: getEnvDurationOrDefault("AUTH_KEY_GRACE_PERIOD", 30*24*time.Hour), // Default to 30 days
		MasterKeyPath:  os.Getenv("AUTH_MASTER_KEY_PATH"),                                 // Optional
		DatabaseFile: getEnvOrDefault(
			"AUTH_DATABASE_FILE",
			"auth.db",
		), // Default to ./auth.db change this later
		PepperFile: getEnvOrDefault("AUTH_PEPPER_FILE", "pepper"), // Default to ./pepper
		BootstrapToken: os.Getenv(
			"BOOTSTRAP_TOKEN",
		), // Optional: if set, required to perform bootstrap
		Env:                  getEnvOrDefault("ENV", "dev"),
		LogLevel:             getEnvOrDefault("LOG_LEVEL", "info"),
		LogFormat:            getEnvOrDefault("LOG_FORMAT", "json"),
		Port:                 getEnvIntOrDefault("PORT", 8080),
		ShutdownGracePeriod:  getEnvDurationOrDefault("SHUTDOWN_GRACE_PERIOD", 10*time.Second),
		HousekeepingInterval: getEnvDurationOrDefault("HOUSEKEEPING_INTERVAL", 1*time.Hour),
	}

	// Parse RSA bits (only relevant for RS256)
	if rsaBitsStr := os.Getenv("AUTH_RSA_BITS"); rsaBitsStr != "" {
		if bits, err := strconv.Atoi(rsaBitsStr); err == nil {
			cfg.RSABits = bits
		}
		// If parsing fails, RSABits remains 0 (will use default in KeyManager)
	}

	// Parse number of keys (default: 3)
	if numKeysStr := os.Getenv("AUTH_NUM_KEYS"); numKeysStr != "" {
		if numKeys, err := strconv.Atoi(numKeysStr); err == nil {
			cfg.NumKeys = numKeys
		}
		// If parsing fails, NumKeys remains 0 (will use default in KeyManager)
	}

	if cfg.Issuer == "" {
		cfg.Issuer = "bartab-auth" // Default issuer (probably should be generated randomly)
	}

	return cfg
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvIntOrDefault(key string, defaultValue int) int {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}

	if intValue, err := strconv.Atoi(value); err == nil {
		return intValue
	}

	return defaultValue
}

func getEnvDurationOrDefault(key string, defaultValue time.Duration) time.Duration {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}

	// Try parsing as duration (e.g., "1h", "30m", "90s")
	if duration, err := time.ParseDuration(value); err == nil {
		return duration
	}

	// Try parsing as integer minutes (for backwards compatibility)
	if minutes, err := strconv.Atoi(value); err == nil {
		return time.Duration(minutes) * time.Minute
	}

	return defaultValue
}
