package http

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/aussiebroadwan/bartab/internal/auth/service"
	"github.com/aussiebroadwan/bartab/pkg/authsdk"
	"github.com/aussiebroadwan/bartab/pkg/httpx"
	"github.com/aussiebroadwan/bartab/pkg/slogx"
)

type InviteMintHandler struct {
	InviteService *service.InviteService
}

// ServeHTTP godoc
//
//	@Summary		User Invitation Endpoint
//	@Description	Mint a user invitation token for inviting new users for a specific client application. This is an admin-only operation.
//	@Tags			Invitations
//	@Accept			json
//	@Produce		json
//	@Param			request	body		authsdk.InviteRequest	true	"Invite request"
//	@Success		200		{object}	authsdk.InviteResponse	"invite_token, client_id, expires_at"
//	@Failure		400		{object}	authsdk.ErrorResponse	"error, error_description"
//	@Failure		401		{object}	authsdk.ErrorResponse	"error, error_description"
//	@Failure		500		{object}	authsdk.ErrorResponse	"error, error_description"
//	@Security		BearerAuth
//	@Router			/v1/invites/mint [post].
func (h *InviteMintHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := slogx.FromContext(ctx)

	// Parse JSON request body
	var req authsdk.InviteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, authsdk.ErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "Invalid JSON body",
		})
		return
	}

	// Validate required fields
	if req.ClientID == "" {
		httpx.WriteJSON(w, http.StatusBadRequest, authsdk.ErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "client_id is required",
		})
		return
	}
	if req.RoleID == "" {
		httpx.WriteJSON(w, http.StatusBadRequest, authsdk.ErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "role_id is required",
		})
		return
	}

	// Get active user ID from context
	userID, ok := ctx.Value(httpx.CtxKeyUserID).(string)
	if !ok || userID == "" {
		httpx.WriteJSON(w, http.StatusUnauthorized, authsdk.ErrorResponse{
			Error:            "unauthorized",
			ErrorDescription: "Authentication required",
		})
		return
	}

	// Set default expiry (1 day from now) if not provided. Should probably have a hard limit too.
	var expiresAt time.Time
	if req.ExpiresAt == 0 {
		expiresAt = time.Now().Add(24 * time.Hour)
	} else {
		expiresAt = time.Unix(req.ExpiresAt, 0)
	}

	// Mint the invite
	token, err := h.InviteService.MintInvite(
		ctx,
		req.ClientID,
		req.RoleID,
		expiresAt,
		req.Reusable,
		userID, // User ID of the admin creating the invite
	)

	if err != nil {
		switch {
		case errors.Is(err, service.ErrAdminInviteCannotBeReusable):
			httpx.WriteJSON(w, http.StatusBadRequest, authsdk.ErrorResponse{
				Error:            "invalid_request",
				ErrorDescription: "Admin invites cannot be reusable",
			})
		case errors.Is(err, service.ErrInvalidClient):
			httpx.WriteJSON(w, http.StatusBadRequest, authsdk.ErrorResponse{
				Error:            "invalid_client",
				ErrorDescription: "Client not found",
			})
		case errors.Is(err, service.ErrInvalidInviteRequest):
			httpx.WriteJSON(w, http.StatusBadRequest, authsdk.ErrorResponse{
				Error:            "invalid_request",
				ErrorDescription: "Invalid invite parameters",
			})
		case errors.Is(err, service.ErrInvalidRole):
			httpx.WriteJSON(w, http.StatusBadRequest, authsdk.ErrorResponse{
				Error:            "invalid_request",
				ErrorDescription: "Invalid role_id",
			})
		default:
			log.Error("failed to mint invite", "err", err)
			httpx.WriteJSON(w, http.StatusInternalServerError, authsdk.ErrorResponse{
				Error:            "server_error",
				ErrorDescription: "Failed to create invite",
			})
		}
		return
	}

	// Return the invite token
	response := authsdk.InviteResponse{
		InviteToken: token,
		ClientID:    req.ClientID,
		ExpiresAt:   expiresAt.Unix(),
	}

	httpx.WriteJSON(w, http.StatusOK, response)
}
