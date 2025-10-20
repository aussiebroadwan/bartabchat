package http

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/aussiebroadwan/bartab/internal/auth/domain"
	"github.com/aussiebroadwan/bartab/internal/auth/service"
	"github.com/aussiebroadwan/bartab/pkg/authsdk"
	"github.com/aussiebroadwan/bartab/pkg/httpx"
	"github.com/aussiebroadwan/bartab/pkg/slogx"
)

type BootstrapHandler struct {
	BootstrapService *service.BootstrapService
}

// ServeHTTP handles the bootstrap endpoint for initial system setup.
//
//	@Summary		Bootstrap the authentication system
//	@Description	Initializes the authentication service by creating the first admin user and OAuth2 client. This endpoint is only available when a bootstrap token is configured and can only be used once.
//	@Tags			Bootstrap
//	@Accept			json
//	@Produce		json
//	@Param			X-Bootstrap-Token	header		string							true	"Bootstrap token for authorization"
//	@Param			request				body		authsdk.BootstrapRequest		true	"Bootstrap configuration"
//	@Success		201					{object}	authsdk.BootstrapResponse		"Successfully bootstrapped system with admin user and client IDs"
//	@Failure		400					{object}	authsdk.ValidationErrorResponse	"Invalid request body or validation failed"
//	@Failure		401					{object}	authsdk.ErrorResponse			"Missing or invalid bootstrap token, or system already bootstrapped"
//	@Failure		404					{object}	authsdk.ErrorResponse			"Bootstrap not enabled (no token configured)"
//	@Failure		500					{object}	authsdk.ErrorResponse			"Failed to create admin user or client"
//	@Router			/v1/bootstrap [post].
func (h *BootstrapHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	l := slogx.FromContext(r.Context())
	l.Info("Starting to bootstrap")

	// 1. Check if enabled
	if h.BootstrapService.Token == "" {
		httpx.WriteJSON(w, http.StatusNotFound, authsdk.ErrorResponse{
			Error:            "not_found",
			ErrorDescription: "Bootstrap endpoint is not enabled",
		})
		return
	}

	// 2. Require bootstrap token header
	token := r.Header.Get("X-Bootstrap-Token")
	if token == "" {
		httpx.WriteJSON(w, http.StatusUnauthorized, authsdk.ErrorResponse{
			Error:            "unauthorized",
			ErrorDescription: "Bootstrap token is required in X-Bootstrap-Token header",
		})
		return
	}

	// 3. Parse request body and validate
	var req authsdk.BootstrapRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, authsdk.ErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "Request body must be valid JSON",
		})
		return
	}
	if errs := req.Validate(); errs != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, authsdk.ValidationErrorResponse{
			Code:    "validation_error",
			Message: "validation failed for some fields",
			Details: errs,
		})
		return
	}

	// 4. Map roles from SDK to domain
	roles := make([]domain.RoleDefinition, len(req.Roles))
	for i, r := range req.Roles {
		roles[i] = domain.RoleDefinition{
			Name:   strings.TrimSpace(r.Name),
			Scopes: r.Scopes,
		}
	}

	// 5. Perform bootstrap
	adminUserID, clientID, clientSecret, err := h.BootstrapService.Bootstrap(
		r.Context(),
		token,
		domain.BootstrapData{
			AdminUsername:      strings.TrimSpace(req.AdminUsername),
			AdminPreferredName: strings.TrimSpace(req.AdminPreferredName),
			AdminPassword:      strings.TrimSpace(req.AdminPassword),
			ClientName:         strings.TrimSpace(req.ClientName),
			ClientScopes:       req.ClientScopes,
			Roles:              roles,
		},
	)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrBootstrapAlready):
			httpx.WriteJSON(
				w,
				http.StatusUnauthorized,
				authsdk.ErrorResponse{
					Error:            "unauthorized",
					ErrorDescription: "System has already been bootstrapped",
				},
			)
		case errors.Is(err, service.ErrBootstrapUnauthorized):
			httpx.WriteJSON(
				w,
				http.StatusUnauthorized,
				authsdk.ErrorResponse{
					Error:            "unauthorized",
					ErrorDescription: "Invalid bootstrap token",
				},
			)
		case errors.Is(err, service.ErrBootstrapFailedToCreateAdmin):
			httpx.WriteJSON(
				w,
				http.StatusInternalServerError,
				authsdk.ErrorResponse{
					Error:            "server_error",
					ErrorDescription: "Failed to create admin user",
				},
			)
		case errors.Is(err, service.ErrBootstrapFailedToCreateClient):
			httpx.WriteJSON(
				w,
				http.StatusInternalServerError,
				authsdk.ErrorResponse{
					Error:            "server_error",
					ErrorDescription: "Failed to create OAuth2 client",
				},
			)
		default:
			httpx.WriteJSON(
				w,
				http.StatusInternalServerError,
				authsdk.ErrorResponse{
					Error:            "server_error",
					ErrorDescription: "An internal error occurred",
				},
			)
		}
		return
	}

	// 6. Respond with created IDs and client secret (only shown once)
	httpx.NoCache(w)
	httpx.WriteJSON(w, http.StatusCreated, authsdk.BootstrapResponse{
		AdminUserID:  adminUserID,
		ClientID:     clientID,
		ClientSecret: clientSecret,
	})
}
