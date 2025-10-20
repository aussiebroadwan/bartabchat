package app

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	httpapi "github.com/aussiebroadwan/bartab/internal/auth/http"
	"github.com/aussiebroadwan/bartab/internal/auth/service"
	"github.com/aussiebroadwan/bartab/internal/auth/store"
	"github.com/aussiebroadwan/bartab/internal/auth/store/drivers/sqlite"
	"github.com/aussiebroadwan/bartab/pkg/cryptox"
	"github.com/aussiebroadwan/bartab/pkg/jwtx"
	"github.com/aussiebroadwan/bartab/pkg/slogx"
)

const (
	// BuildVersion should be set at build time via ldflags. Later problem
	BuildVersion = "v0.1.0"
)

// Application encapsulates the auth service application with all its dependencies
type Application struct {
	cfg    Config
	logger *slog.Logger

	// Core dependencies
	db         store.Store
	keyManager *jwtx.KeyManager

	// Services
	tokenService        *service.TokenService
	userService         *service.UserService
	rolesService        *service.RolesService
	bootstrapService    *service.BootstrapService
	inviteService       *service.InviteService
	mfaService          *service.MFAService
	clientService       *service.ClientService
	housekeepingService *service.HousekeepingService
	authorizeService    *service.AuthorizeService
	keyRotationService  *service.KeyRotationService // Optional: only in persistent mode

	// HTTP server
	server *http.Server
	router *httpapi.Router
}

// New creates a new Application instance with all dependencies initialized
func New(cfg Config) (*Application, error) {
	app := &Application{
		cfg: cfg,
		logger: slogx.New(slogx.Config{
			Service: "auth-service",
			Version: BuildVersion,
			Env:     cfg.Env,
			Level:   cfg.LogLevel,
			Format:  cfg.LogFormat,
		}),
	}

	// Set pepper path for password hashing
	cryptox.SetPepperPath(app.cfg.PepperFile)

	// Initialize database first (required for persistent keys)
	if err := app.initDatabase(); err != nil {
		return nil, err
	}

	// Initialize JWT key manager (after database for persistent mode)
	ctx := context.Background()
	keyManager, err := InitAuthKeys(ctx, app.cfg, app.db, app.logger)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize JWT keys: %w", err)
	}
	app.keyManager = keyManager

	app.initServices()
	app.initHTTP()

	return app, nil
}

// Run starts the application and blocks until shutdown is requested
func (app *Application) Run() error {
	// Start housekeeping service
	app.housekeepingService.Start()

	app.logger.Info("auth service starting", "port", app.cfg.Port, "version", BuildVersion)

	// Start server in a goroutine
	serverErrors := make(chan error, 1)
	go func() {
		serverErrors <- app.server.ListenAndServe()
	}()

	// Setup signal handling for graceful shutdown
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)

	// Block until we receive a shutdown signal or server error
	select {
	case err := <-serverErrors:
		if err != nil && err != http.ErrServerClosed {
			return fmt.Errorf("server failed: %w", err)
		}
	case sig := <-shutdown:
		app.logger.Info("shutdown signal received", "signal", sig)

		// Perform graceful shutdown
		if err := app.Shutdown(); err != nil {
			return fmt.Errorf("graceful shutdown failed: %w", err)
		}
	}

	return nil
}

// Shutdown gracefully shuts down the application
func (app *Application) Shutdown() error {
	app.logger.Info("shutting down auth service...")

	// Give outstanding requests a deadline for completion
	ctx, cancel := context.WithTimeout(context.Background(), app.cfg.ShutdownGracePeriod)
	defer cancel()

	// Shutdown the HTTP server
	if err := app.server.Shutdown(ctx); err != nil {
		app.logger.Error("graceful server shutdown failed", "error", err)
		if err := app.server.Close(); err != nil {
			app.logger.Error("error closing server", "error", err)
		}
	}

	// Stop the housekeeping service
	app.housekeepingService.Stop()

	// Close database connection
	if err := app.db.Close(); err != nil {
		app.logger.Error("error closing database", "error", err)
		return err
	}

	app.logger.Info("auth service stopped")
	return nil
}

// initDatabase initializes the database and applies migrations
func (app *Application) initDatabase() error {
	host := fmt.Sprintf("file:%s?_busy_timeout=5000&_journal_mode=WAL", app.cfg.DatabaseFile)
	db, err := sqlite.NewStore(host)
	if err != nil {
		return fmt.Errorf("failed to initialize database: %w", err)
	}
	app.db = db

	if err := db.ApplyMigrations(); err != nil {
		_ = db.Close()
		return fmt.Errorf("failed to apply database migrations: %w", err)
	}

	app.logger.Info("database migrations applied successfully")
	return nil
}

// initServices initializes all business logic services
func (app *Application) initServices() {
	app.tokenService = &service.TokenService{
		KeyManager: app.keyManager, // Pass KeyManager for multi-key support
		Store:      app.db,
		Issuer:     app.cfg.Issuer,
		AccessTTL:  jwtx.DefaultAccessTokenTTL,
		RefreshTTL: jwtx.DefaultRefreshTokenTTL,
	}

	app.userService = &service.UserService{Store: app.db}
	app.rolesService = &service.RolesService{Store: app.db}
	app.bootstrapService = &service.BootstrapService{
		Store: app.db,
		Token: app.cfg.BootstrapToken,
	}
	app.inviteService = &service.InviteService{Store: app.db}
	app.mfaService = &service.MFAService{
		Store:  app.db,
		Issuer: app.cfg.Issuer,
	}
	app.clientService = &service.ClientService{Store: app.db}
	app.authorizeService = &service.AuthorizeService{
		Store:   app.db,
		CodeTTL: 5 * time.Minute,
	}

	app.housekeepingService = service.NewHousekeepingService(
		app.db,
		app.logger,
		app.cfg.HousekeepingInterval,
	)

	// Initialize KeyRotationService for both ephemeral and persistent modes
	if app.cfg.KeyStorageMode == "persistent" {
		app.keyRotationService = &service.KeyRotationService{
			Store:       app.db, // Database persistence
			KeyManager:  app.keyManager,
			Algorithm:   app.cfg.Algorithm,
			RSABits:     app.cfg.RSABits,
			GracePeriod: app.cfg.KeyGracePeriod,
		}
		app.logger.Info("key rotation service enabled (persistent mode)")
	} else {
		// Ephemeral mode - still allow runtime rotation, just no database persistence
		app.keyRotationService = &service.KeyRotationService{
			Store:      nil, // No database persistence
			KeyManager: app.keyManager,
			Algorithm:  app.cfg.Algorithm,
			RSABits:    app.cfg.RSABits,
		}
		app.logger.Info("key rotation service enabled (ephemeral mode)")
	}
}

// initHTTP initializes the HTTP router and server
func (app *Application) initHTTP() {
	router := httpapi.NewRouter(
		app.keyManager.KeySet,
		app.keyManager.Verifier,
		app.cfg.Issuer,
		BuildVersion,
		app.db,
		app.logger,
	)

	// Wire services to router
	router.TokenService = app.tokenService
	router.UserService = app.userService
	router.RolesService = app.rolesService
	router.BootstrapService = app.bootstrapService
	router.InviteService = app.inviteService
	router.MFAService = app.mfaService
	router.ClientService = app.clientService
	router.AuthorizeService = app.authorizeService
	router.KeyRotationService = app.keyRotationService // nil in ephemeral mode
	router.ApplyRoutes()

	app.router = router

	// Initialize HTTP server
	app.server = &http.Server{
		Addr:              fmt.Sprintf(":%d", app.cfg.Port),
		Handler:           router,
		ReadHeaderTimeout: 3 * time.Second,
	}
}
