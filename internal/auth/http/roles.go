package http

import (
	"net/http"

	"github.com/aussiebroadwan/bartab/internal/auth/service"
	"github.com/aussiebroadwan/bartab/pkg/authsdk"
	"github.com/aussiebroadwan/bartab/pkg/httpx"
	"github.com/aussiebroadwan/bartab/pkg/slogx"
)

type RolesHandler struct {
	RolesService *service.RolesService
}

// ServeHTTP handles the list roles endpoint
//
//	@Summary		List all roles
//	@Description	Returns a list of all available roles in the system. Requires admin:read scope.
//	@Tags			Roles
//	@Produce		json
//	@Success		200	{object}	authsdk.ListRolesResponse	"List of roles"
//	@Failure		401	{object}	authsdk.ErrorResponse		"Unauthorized - missing or invalid token"
//	@Failure		403	{object}	authsdk.ErrorResponse		"Forbidden - missing required scope"
//	@Failure		500	{object}	authsdk.ErrorResponse		"Internal server error"
//	@Security		BearerAuth
//	@Router			/v1/roles [get].
func (h *RolesHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := slogx.FromContext(ctx)

	// Get all roles from the service
	roles, err := h.RolesService.ListAll(ctx)
	if err != nil {
		log.Error("failed to list roles", "error", err)
		httpx.WriteJSON(w, http.StatusInternalServerError, authsdk.ErrorResponse{
			Error:            "server_error",
			ErrorDescription: "Failed to retrieve roles",
		})
		return
	}

	// Convert to response format
	response := authsdk.ListRolesResponse{
		Roles: make([]authsdk.RoleInfo, len(roles)),
	}

	for i, role := range roles {
		response.Roles[i] = authsdk.RoleInfo{
			ID:     role.ID,
			Name:   role.Name,
			Scopes: role.Scopes,
		}
	}

	httpx.WriteJSON(w, http.StatusOK, response)
}
