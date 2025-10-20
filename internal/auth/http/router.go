package http

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/aussiebroadwan/bartab/internal/auth/service"
	"github.com/aussiebroadwan/bartab/internal/auth/store"
	"github.com/aussiebroadwan/bartab/pkg/httpx"
	"github.com/aussiebroadwan/bartab/pkg/jwtx"
	"github.com/aussiebroadwan/bartab/pkg/slogx"

	_ "github.com/aussiebroadwan/bartab/api/auth" // Swagger docs
	httpSwagger "github.com/swaggo/http-swagger"
)

// Router holds shared dependencies for HTTP handlers.
type Router struct {
	Mux         *http.ServeMux
	middlewares []httpx.Middleware

	keys         *jwtx.KeySet
	verifier     jwtx.Verifier
	issuer       string
	buildVersion string
	startTime    time.Time
	logger       *slog.Logger

	store              store.Store
	TokenService       *service.TokenService
	UserService        *service.UserService
	RolesService       *service.RolesService
	BootstrapService   *service.BootstrapService
	InviteService      *service.InviteService
	MFAService         *service.MFAService
	ClientService      *service.ClientService
	AuthorizeService   *service.AuthorizeService
	KeyRotationService *service.KeyRotationService // Optional: only available in persistent mode
}

func NewRouter(
	keys *jwtx.KeySet,
	verifier jwtx.Verifier,
	issuer, buildVersion string,
	st store.Store,
	logger *slog.Logger,
) *Router {
	r := &Router{
		Mux:          http.NewServeMux(),
		keys:         keys,
		verifier:     verifier,
		issuer:       issuer,
		buildVersion: buildVersion,
		startTime:    time.Now(),
		store:        st,
		logger:       logger,
	}

	// Set default middleware chain
	r.middlewares = []httpx.Middleware{
		slogx.HTTPMiddleware(r.logger),
	}

	return r
}

func (r *Router) ApplyRoutes() {
	r.registerOAuth2()
	r.registerUsers()
	r.registerInvites()
	r.registerRoles()
	r.registerClients()
	r.registerMFA()
	r.registerKeyRotation()
	r.registerSystem()
	r.registerBootstrap()

	r.Mux.Handle("/swagger/", httpSwagger.Handler())
}

// ServeHTTP implements http.Handler for Router and applies the global middleware chain.
//
//	@title			BarTab Authentication Service API
//	@version		0.1.0
//	@description	Attempting to be OAuth2-compliant for our authentication service providing token management with JWT-based access tokens.
//	@description
//	@description				All tokens are signed using RS256 (RSA-SHA256) and can be verified using the JWKS endpoint.
//
//	@contact.name				AussieBroadWAN Team
//	@contact.url				https://github.com/aussiebroadwan/bartab
//
//	@license.name				MIT
//	@license.url				https://opensource.org/licenses/MIT
//
//	@host						localhost:8080
//	@BasePath					/
//
//	@schemes					http https
//
//	@securityDefinitions.apikey	BearerAuth
//	@in							header
//	@name						Authorization
//	@description				JWT access token. Format: "Bearer {token}".
func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	httpx.Chain(r.Mux, r.middlewares...).ServeHTTP(w, req)
}

func (r *Router) registerOAuth2() {
	authorizeHandler := &AuthorizeHandler{
		AuthorizeService: r.AuthorizeService,
		Verifier:         r.verifier,
		Logger:           r.logger,
	}

	// GET /authorize - lenient rate limit (mostly just displays forms)
	r.Mux.Handle("GET /v1/oauth2/authorize",
		httpx.Chain(http.HandlerFunc(authorizeHandler.HandleGet),
			httpx.RateLimitByIP(httpx.LenientLimit),
		),
	)

	// POST /authorize - strict rate limit (authentication attempts)
	// Note: Rate limited by IP + username form field to prevent brute force
	r.Mux.Handle("POST /v1/oauth2/authorize",
		httpx.Chain(http.HandlerFunc(authorizeHandler.HandlePost),
			httpx.RateLimitByIPAndFormField(httpx.StrictLimit, "username"),
		),
	)

	// POST /token - strict rate limit by IP (covers all grant types)
	// Individual grant types have different security implications, but we limit all at IP level
	tokenHandler := &TokenHandler{TokenService: r.TokenService}
	r.Mux.Handle("POST /v1/oauth2/token",
		httpx.Chain(tokenHandler,
			httpx.RateLimitByIP(httpx.StrictLimit),
		),
	)

	// POST /revoke - moderate rate limit
	revokeHandler := &RevokeHandler{TokenService: r.TokenService}
	r.Mux.Handle("POST /v1/oauth2/revoke",
		httpx.Chain(revokeHandler,
			httpx.RateLimitByIP(httpx.ModerateLimit),
		),
	)

	// GET /jwks.json - public endpoint with high limit
	r.Mux.Handle("GET /.well-known/jwks.json",
		httpx.Chain(JWKSHandler(r.keys),
			httpx.RateLimitByIP(httpx.PublicLimit),
		),
	)

	// Introspection endpoint (RFC7662) - requires authentication, moderate limit
	introspectHandler := &IntrospectHandler{Verifier: r.verifier}
	r.Mux.Handle("POST /v1/oauth2/introspect",
		httpx.Chain(introspectHandler,
			httpx.AuthnMiddleware(r.verifier),
			httpx.RateLimitByUser(httpx.ModerateLimit),
		),
	)
}

func (r *Router) registerUsers() {
	h := &UserInfoHandler{
		UserService:  r.UserService,
		RolesService: r.RolesService,
	}

	// Authenticated endpoint - lenient rate limit by user
	secured := httpx.Chain(h,
		httpx.AuthnMiddleware(r.verifier),     // verify JWT (iss/aud/exp)
		httpx.RequireAnyScope("profile:read"), // enforce scopes
		httpx.RateLimitByUser(httpx.LenientLimit),
	)

	r.Mux.Handle("GET /v1/userinfo", secured)
}

func (r *Router) registerInvites() {
	mintHandler := &InviteMintHandler{InviteService: r.InviteService}
	redeemHandler := &InviteRedeemHandler{InviteService: r.InviteService}

	// POST /invites/mint - moderate rate limit by user (admin operation)
	securedMint := httpx.Chain(mintHandler,
		httpx.AuthnMiddleware(r.verifier),    // verify JWT (iss/exp)
		httpx.RequireAnyScope("admin:write"), // enforce admin scope
		httpx.RateLimitByUser(httpx.ModerateLimit),
	)

	r.Mux.Handle("POST /v1/invites/mint", securedMint)

	// POST /invites/redeem - strict rate limit by IP (public signup endpoint)
	r.Mux.Handle("POST /v1/invites/redeem",
		httpx.Chain(redeemHandler,
			httpx.RateLimitByIP(httpx.StrictLimit),
		),
	)
}

func (r *Router) registerRoles() {
	h := &RolesHandler{RolesService: r.RolesService}

	// GET /roles - moderate rate limit by user (admin read operation)
	secured := httpx.Chain(h,
		httpx.AuthnMiddleware(r.verifier),   // verify JWT (iss/exp)
		httpx.RequireAnyScope("admin:read"), // enforce admin scope
		httpx.RateLimitByUser(httpx.ModerateLimit),
	)

	r.Mux.Handle("GET /v1/roles", secured)
}

func (r *Router) registerClients() {
	h := &ClientsHandler{ClientService: r.ClientService}

	// POST /v1/clients - Create client (requires admin:write) - moderate rate limit
	securedCreate := httpx.Chain(http.HandlerFunc(h.HandleCreate),
		httpx.AuthnMiddleware(r.verifier),
		httpx.RequireAnyScope("admin:write"),
		httpx.RateLimitByUser(httpx.ModerateLimit),
	)

	// GET /v1/clients - List clients (requires admin:read) - moderate rate limit
	securedList := httpx.Chain(http.HandlerFunc(h.HandleList),
		httpx.AuthnMiddleware(r.verifier),
		httpx.RequireAnyScope("admin:read"),
		httpx.RateLimitByUser(httpx.ModerateLimit),
	)

	// DELETE /v1/clients/{id} - Delete client (requires admin:write) - moderate rate limit
	securedDelete := httpx.Chain(http.HandlerFunc(h.HandleDelete),
		httpx.AuthnMiddleware(r.verifier),
		httpx.RequireAnyScope("admin:write"),
		httpx.RateLimitByUser(httpx.ModerateLimit),
	)

	r.Mux.Handle("POST /v1/clients", securedCreate)
	r.Mux.Handle("GET /v1/clients", securedList)
	r.Mux.Handle("DELETE /v1/clients/{id}", securedDelete)
}

func (r *Router) registerBootstrap() {
	// POST /bootstrap - very strict rate limit by IP (one-time setup endpoint)
	bootstrapHandler := &BootstrapHandler{BootstrapService: r.BootstrapService}
	r.Mux.Handle("POST /v1/bootstrap",
		httpx.Chain(bootstrapHandler,
			httpx.RateLimitByIP(httpx.StrictLimit),
		),
	)
}

func (r *Router) registerMFA() {
	h := &MFAHandler{
		MFAService:  r.MFAService,
		UserService: r.UserService,
	}

	// POST /mfa/totp/enroll - moderate rate limit by user
	securedEnroll := httpx.Chain(http.HandlerFunc(h.HandleEnroll),
		httpx.AuthnMiddleware(r.verifier),
		httpx.RateLimitByUser(httpx.ModerateLimit),
	)

	// POST /mfa/totp/verify - strict rate limit by user (prevent brute force of TOTP codes)
	securedVerify := httpx.Chain(http.HandlerFunc(h.HandleVerify),
		httpx.AuthnMiddleware(r.verifier),
		httpx.RateLimitByUser(httpx.StrictLimit),
	)

	// POST /mfa/backup-codes - moderate rate limit by user
	securedRegenerate := httpx.Chain(http.HandlerFunc(h.HandleRegenerateBackupCodes),
		httpx.AuthnMiddleware(r.verifier),
		httpx.RateLimitByUser(httpx.ModerateLimit),
	)

	// DELETE /mfa/totp - moderate rate limit by user
	securedRemove := httpx.Chain(http.HandlerFunc(h.HandleRemove),
		httpx.AuthnMiddleware(r.verifier),
		httpx.RateLimitByUser(httpx.ModerateLimit),
	)

	r.Mux.Handle("POST /v1/mfa/totp/enroll", securedEnroll)
	r.Mux.Handle("POST /v1/mfa/totp/verify", securedVerify)
	r.Mux.Handle("POST /v1/mfa/backup-codes", securedRegenerate)
	r.Mux.Handle("DELETE /v1/mfa/totp", securedRemove)
}

func (r *Router) registerKeyRotation() {
	// Key rotation endpoints are available in both ephemeral and persistent modes
	// Ephemeral mode: Keys rotated in-memory only (lost on restart)
	// Persistent mode: Keys persisted to database and survive restarts
	h := &KeyRotationHandler{KeyRotationService: r.KeyRotationService}

	// POST /v1/keys/rotate - Rotate keys (requires admin:write) - moderate rate limit
	securedRotate := httpx.Chain(http.HandlerFunc(h.HandleRotate),
		httpx.AuthnMiddleware(r.verifier),
		httpx.RequireAnyScope("admin:write"),
		httpx.RateLimitByUser(httpx.ModerateLimit),
	)

	// GET /v1/keys - List keys (requires admin:read) - moderate rate limit
	securedList := httpx.Chain(http.HandlerFunc(h.HandleListKeys),
		httpx.AuthnMiddleware(r.verifier),
		httpx.RequireAnyScope("admin:read"),
		httpx.RateLimitByUser(httpx.ModerateLimit),
	)

	// POST /v1/keys/{kid}/retire - Retire key (requires admin:write) - moderate rate limit
	securedRetire := httpx.Chain(http.HandlerFunc(h.HandleRetireKey),
		httpx.AuthnMiddleware(r.verifier),
		httpx.RequireAnyScope("admin:write"),
		httpx.RateLimitByUser(httpx.ModerateLimit),
	)

	r.Mux.Handle("POST /v1/keys/rotate", securedRotate)
	r.Mux.Handle("GET /v1/keys", securedList)
	r.Mux.Handle("POST /v1/keys/{kid}/retire", securedRetire)
}

func (r *Router) registerSystem() {
	// Health check endpoints - lenient rate limits (monitoring systems may poll frequently)
	r.Mux.Handle("GET /livez",
		httpx.Chain(LivezHandler(r.startTime, r.buildVersion),
			httpx.RateLimitByIP(httpx.LenientLimit),
		),
	)
	r.Mux.Handle("GET /readyz",
		httpx.Chain(ReadyzHandler(r.startTime, r.buildVersion, r.store, r.keys),
			httpx.RateLimitByIP(httpx.LenientLimit),
		),
	)
}
