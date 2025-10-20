package http

import (
	"errors"
	"net/http"

	"github.com/aussiebroadwan/bartab/internal/auth/service"
	"github.com/aussiebroadwan/bartab/pkg/authsdk"
	"github.com/aussiebroadwan/bartab/pkg/httpx"
	"github.com/aussiebroadwan/bartab/pkg/slogx"
)

type InviteRedeemHandler struct {
	InviteService *service.InviteService
}

// ServeHTTP godoc
//
//	@Summary		Redeem Invitation Endpoint
//	@Description	Redeem an invitation token to create a new user account
//	@Tags			Invitations
//	@Accept			x-www-form-urlencoded
//	@Produce		json
//	@Param			invite_token	formData	string							true	"Invite token from mint endpoint"
//	@Param			username		formData	string							true	"Desired username"
//	@Param			password		formData	string							true	"User password"
//	@Param			client_id		formData	string							true	"Client ID the invite was issued for"
//	@Success		200				{object}	authsdk.RedeemInviteResponse	"user_id, username"
//	@Failure		400				{object}	authsdk.ErrorResponse			"error, error_description"
//	@Failure		500				{object}	authsdk.ErrorResponse			"error, error_description"
//	@Router			/v1/invites/redeem [post].
func (h *InviteRedeemHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := slogx.FromContext(ctx)

	// Parse URL-encoded form data
	if err := r.ParseForm(); err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, authsdk.ErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "Invalid form data",
		})
		return
	}

	// Extract form fields
	inviteToken := r.FormValue("invite_token")
	username := r.FormValue("username")
	password := r.FormValue("password")
	clientID := r.FormValue("client_id")

	// Validate required fields
	if inviteToken == "" {
		httpx.WriteJSON(w, http.StatusBadRequest, authsdk.ErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "invite_token is required",
		})
		return
	}
	if username == "" {
		httpx.WriteJSON(w, http.StatusBadRequest, authsdk.ErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "username is required",
		})
		return
	}
	if password == "" {
		httpx.WriteJSON(w, http.StatusBadRequest, authsdk.ErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "password is required",
		})
		return
	}
	if clientID == "" {
		httpx.WriteJSON(w, http.StatusBadRequest, authsdk.ErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "client_id is required",
		})
		return
	}

	// Redeem the invite
	user, err := h.InviteService.RedeemInvite(ctx, inviteToken, username, password, clientID)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrInviteNotFound):
			httpx.WriteJSON(w, http.StatusBadRequest, authsdk.ErrorResponse{
				Error:            "invalid_grant",
				ErrorDescription: "Invite token is invalid or expired",
			})
		case errors.Is(err, service.ErrInviteAlreadyUsed):
			httpx.WriteJSON(w, http.StatusBadRequest, authsdk.ErrorResponse{
				Error:            "invalid_grant",
				ErrorDescription: "Invite has already been used",
			})
		case errors.Is(err, service.ErrUsernameAlreadyTaken):
			httpx.WriteJSON(w, http.StatusBadRequest, authsdk.ErrorResponse{
				Error:            "invalid_request",
				ErrorDescription: "Username is already taken",
			})
		case errors.Is(err, service.ErrInviteClientMismatch):
			httpx.WriteJSON(w, http.StatusBadRequest, authsdk.ErrorResponse{
				Error:            "invalid_grant",
				ErrorDescription: "Invite was issued for a different client",
			})
		case errors.Is(err, service.ErrInvalidInviteRequest):
			httpx.WriteJSON(w, http.StatusBadRequest, authsdk.ErrorResponse{
				Error:            "invalid_request",
				ErrorDescription: "Invalid invite redemption parameters",
			})
		default:
			log.Error("failed to redeem invite", "err", err)
			httpx.WriteJSON(w, http.StatusInternalServerError, authsdk.ErrorResponse{
				Error:            "server_error",
				ErrorDescription: "Failed to redeem invite",
			})
		}
		return
	}

	// Return success response
	response := authsdk.RedeemInviteResponse{
		UserID:   user.ID,
		Username: user.Username,
	}

	httpx.WriteJSON(w, http.StatusOK, response)
}
