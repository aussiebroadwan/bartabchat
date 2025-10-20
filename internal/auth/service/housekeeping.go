package service

import (
	"context"
	"log/slog"
	"time"

	"github.com/aussiebroadwan/bartab/internal/auth/store"
)

// HousekeepingService periodically cleans up expired database records
// to prevent unbounded growth of invites, refresh_tokens, and mfa_sessions.
type HousekeepingService struct {
	Store    store.Store
	Logger   *slog.Logger
	Interval time.Duration

	// Internal channels for lifecycle management
	stopCh chan struct{}
	doneCh chan struct{}
}

// NewHousekeepingService creates a new housekeeping service with the given interval.
// If interval is 0 or negative, defaults to 1 hour.
func NewHousekeepingService(store store.Store, logger *slog.Logger, interval time.Duration) *HousekeepingService {
	if interval <= 0 {
		interval = 1 * time.Hour
	}

	return &HousekeepingService{
		Store:    store,
		Logger:   logger,
		Interval: interval,
		stopCh:   make(chan struct{}),
		doneCh:   make(chan struct{}),
	}
}

// Start begins the background worker that periodically runs cleanup.
// This is non-blocking and should be called after the database is ready.
// Call Stop() to gracefully shutdown the worker.
func (s *HousekeepingService) Start() {
	go s.run()
	s.Logger.Info("housekeeping service started", "interval", s.Interval)
}

// Stop gracefully shuts down the background worker.
// Blocks until the worker has finished any in-progress cleanup.
func (s *HousekeepingService) Stop() {
	close(s.stopCh)
	<-s.doneCh
	s.Logger.Info("housekeeping service stopped")
}

// run is the main background worker loop.
func (s *HousekeepingService) run() {
	defer close(s.doneCh)

	ticker := time.NewTicker(s.Interval)
	defer ticker.Stop()

	// Run cleanup immediately on startup
	s.cleanup()

	for {
		select {
		case <-ticker.C:
			s.cleanup()
		case <-s.stopCh:
			return
		}
	}
}

// cleanup performs the actual deletion of expired records.
// Each deletion is independent - failures in one won't stop the others.
func (s *HousekeepingService) cleanup() {
	ctx := context.Background()
	s.Logger.Info("starting housekeeping cleanup")

	var totalDeleted int

	// Clean expired refresh tokens
	if err := s.Store.RefreshTokens().DeleteExpiredRefreshTokens(ctx); err != nil {
		s.Logger.Error("failed to delete expired refresh tokens", "error", err)
	} else {
		s.Logger.Debug("deleted expired refresh tokens")
		totalDeleted++
	}

	// Clean expired invites
	if err := s.Store.Invites().DeleteExpiredInvites(ctx); err != nil {
		s.Logger.Error("failed to delete expired invites", "error", err)
	} else {
		s.Logger.Debug("deleted expired invites")
		totalDeleted++
	}

	// Clean expired MFA sessions
	if err := s.Store.MFASessions().DeleteExpiredMFASessions(ctx); err != nil {
		s.Logger.Error("failed to delete expired MFA sessions", "error", err)
	} else {
		s.Logger.Debug("deleted expired MFA sessions")
		totalDeleted++
	}

	// Clean expired signing keys (for persistent key mode)
	if err := s.Store.SigningKeys().DeleteExpiredSigningKeys(ctx); err != nil {
		s.Logger.Error("failed to delete expired signing keys", "error", err)
	} else {
		s.Logger.Debug("deleted expired signing keys")
		totalDeleted++
	}

	s.Logger.Info("housekeeping cleanup completed", "successful_cleanups", totalDeleted)
}
