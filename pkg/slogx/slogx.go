package slogx

import (
	"log/slog"
	"os"
	"strings"
)

type Config struct {
	Service string
	Version string
	Env     string // e.g. "dev", "prod"
	Level   string // e.g. "debug", "info", "warn", "error"
	Format  string // e.g. "json", "text"
}

// New returns a configured slog.Logger instance.
func New(cfg Config) *slog.Logger {
	var handler slog.Handler

	level := parseLevel(cfg.Level)
	opts := &slog.HandlerOptions{
		AddSource: cfg.Env == "dev", // Add source info in dev mode
		Level:     level,
	}

	switch strings.ToLower(cfg.Format) {
	case "text":
		handler = slog.NewTextHandler(os.Stdout, opts)
	default:
		handler = slog.NewJSONHandler(os.Stdout, opts)
	}

	logger := slog.New(handler).With(
		"service", cfg.Service,
		"version", cfg.Version,
		"env", cfg.Env,
	)

	slog.SetDefault(logger)
	return logger
}

// parseLevel maps a string to slog.Level.
func parseLevel(lvl string) slog.Level {
	switch strings.ToLower(lvl) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
