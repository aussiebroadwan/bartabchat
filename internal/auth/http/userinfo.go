package http

import (
	"net/http"

	"github.com/aussiebroadwan/bartab/internal/auth/service"
	"github.com/aussiebroadwan/bartab/pkg/authsdk"
	"github.com/aussiebroadwan/bartab/pkg/httpx"
	"github.com/aussiebroadwan/bartab/pkg/slogx"
)

type UserInfoHandler struct {
	UserService  *service.UserService
	RolesService *service.RolesService
}

// ServeHTTP handles the OAuth2 UserInfo endpoint.
//
//	@Summary		Get user information
//	@Description	Returns information about the authenticated user. Requires 'profile:read' scope.
//	@Tags			OAuth2
//	@Security		BearerAuth
//	@Produce		json
//	@Success		200	{object}	authsdk.UserInfoResponse	"User information (user_id, username, preferred_name, role)"
//	@Failure		401	{object}	authsdk.ErrorResponse		"Invalid or missing access token"
//	@Failure		500	{object}	authsdk.ErrorResponse		"Internal server error"
//	@Router			/v1/userinfo [get].
func (h *UserInfoHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := slogx.FromContext(ctx)

	// Get subject (user ID) from request context.
	userID, ok := ctx.Value(httpx.CtxKeyUserID).(string)
	if !ok || userID == "" {
		authsdk.ErrInvalidToken.WriteError(w)
		return
	}

	user, err := h.UserService.GetUserByID(ctx, userID)
	if err != nil {
		log.Warn("failed to load user", "user_id", userID, "err", err)
		authsdk.ErrServerError.WriteError(w)
		return
	}

	// Fetch user's role
	role, err := h.RolesService.GetRoleByID(ctx, user.RoleID)
	if err != nil {
		log.Warn("failed to load role", "user_id", userID, "role_id", user.RoleID, "err", err)
		authsdk.ErrServerError.WriteError(w)
		return
	}

	// Build response with user information
	response := authsdk.UserInfoResponse{
		UserID:        user.ID,
		Username:      user.Username,
		PreferredName: user.PreferredName,
		Role:          role.Name,
	}

	httpx.NoCache(w)
	httpx.WriteJSON(w, http.StatusOK, response)
}
