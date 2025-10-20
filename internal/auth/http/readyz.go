package http

import (
	"net/http"
	"time"

	"github.com/aussiebroadwan/bartab/internal/auth/store"
	"github.com/aussiebroadwan/bartab/pkg/authsdk"
	"github.com/aussiebroadwan/bartab/pkg/httpx"
	"github.com/aussiebroadwan/bartab/pkg/jwtx"
)

// ReadyzHandler godoc
//
//	@Summary		Readiness Check Endpoint
//	@Description	Readiness probe endpoint returning service health status and checks for critical dependencies
//	@Description	Includes uptime, version, and status of database, signer, and cache components
//	@Tags			Health
//	@Produce		json
//	@Success		200	{object}	authsdk.HealthResponse	"status, uptime, version, checks"
//	@Failure		503	{object}	authsdk.HealthResponse	"status, uptime, version, checks - service not ready"
//	@Router			/readyz [get].
func ReadyzHandler(
	startTime time.Time,
	version string,
	st store.Store,
	keys *jwtx.KeySet,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		checks := &authsdk.HealthChecks{
			Database: "ok",
			Signer:   "ok",
		}
		overallStatus := "ok"
		statusCode := http.StatusOK

		// Check database connectivity
		if err := st.Ping(r.Context()); err != nil {
			checks.Database = "error: " + err.Error()
			overallStatus = "degraded"
			statusCode = http.StatusServiceUnavailable
		}

		// Check if JWT signer/verifier has keys loaded
		if !keys.IsReady() {
			checks.Signer = "error: no keys loaded"
			overallStatus = "degraded"
			statusCode = http.StatusServiceUnavailable
		}

		response := authsdk.HealthResponse{
			Status:  overallStatus,
			Uptime:  time.Since(startTime).String(),
			Version: version,
			Checks:  checks,
		}
		httpx.WriteJSON(w, statusCode, response)
	}
}
