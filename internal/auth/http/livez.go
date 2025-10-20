package http

import (
	"net/http"
	"time"

	"github.com/aussiebroadwan/bartab/pkg/authsdk"
	"github.com/aussiebroadwan/bartab/pkg/httpx"
)

// LivezHandler godoc
//
//	@Summary		Health Check Endpoint
//	@Description	Liveness probe endpoint returning basic service health status, uptime, and version information
//	@Description	This endpoint always returns 200 OK if the service is running
//	@Tags			Health
//	@Produce		json
//	@Success		200	{object}	authsdk.HealthResponse	"status, uptime, version"
//	@Router			/livez [get].
func LivezHandler(startTime time.Time, version string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		response := authsdk.HealthResponse{
			Status:  "ok",
			Uptime:  time.Since(startTime).String(),
			Version: version,
		}
		httpx.WriteJSON(w, http.StatusOK, response)
	}
}
