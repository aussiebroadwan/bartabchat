package http

import (
	"encoding/json"
	"net/http"

	"github.com/aussiebroadwan/bartab/internal/auth/service"
	"github.com/aussiebroadwan/bartab/pkg/authsdk"
	"github.com/aussiebroadwan/bartab/pkg/httpx"
	"github.com/aussiebroadwan/bartab/pkg/slogx"
)

// MFAHandler handles all MFA-related endpoints.
type MFAHandler struct {
	MFAService  *service.MFAService
	UserService *service.UserService
}

// HandleEnroll handles POST /v1/mfa/totp/enroll
//
//	@Summary		Enroll in TOTP MFA
//	@Description	Generates a TOTP secret for the authenticated user and returns it with a QR code.
//	@Tags			MFA
//	@Security		BearerAuth
//	@Produce		json
//	@Success		200	{object}	authsdk.TOTPEnrollResponse	"TOTP secret and QR code"
//	@Failure		400	{object}	authsdk.ErrorResponse		"MFA already enabled"
//	@Failure		401	{object}	authsdk.ErrorResponse		"Invalid or missing access token"
//	@Failure		500	{object}	authsdk.ErrorResponse		"Internal server error"
//	@Router			/v1/mfa/totp/enroll [post].
func (h *MFAHandler) HandleEnroll(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := slogx.FromContext(ctx)

	// Get user ID from context (injected by AuthnMiddleware)
	userID, ok := ctx.Value(httpx.CtxKeyUserID).(string)
	if !ok || userID == "" {
		authsdk.ErrInvalidToken.WriteError(w)
		return
	}

	// Get user to fetch username
	user, err := h.UserService.GetUserByID(ctx, userID)
	if err != nil {
		log.Warn("failed to load user", "user_id", userID, "err", err)
		authsdk.ErrServerError.WriteError(w)
		return
	}

	// Enroll in TOTP
	enrollData, err := h.MFAService.EnrollTOTP(ctx, userID, user.Username)
	if err != nil {
		if err == service.ErrMFAAlreadyEnabled {
			log.Warn("MFA already enabled", "user_id", userID)
			httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{
				"error":             "mfa_already_enabled",
				"error_description": "MFA is already enabled for this user",
			})
			return
		}
		log.Error("failed to enroll TOTP", "user_id", userID, "err", err)
		authsdk.ErrServerError.WriteError(w)
		return
	}

	httpx.NoCache(w)
	httpx.WriteJSON(w, http.StatusOK, authsdk.TOTPEnrollResponse{
		Secret:  enrollData.Secret,
		QRCode:  enrollData.QRCode,
		Issuer:  enrollData.Issuer,
		Account: enrollData.Account,
	})
}

// HandleVerify handles POST /v1/mfa/totp/verify
//
//	@Summary		Verify TOTP code and enable MFA
//	@Description	Verifies a TOTP code and enables MFA for the user. Returns backup codes.
//	@Tags			MFA
//	@Security		BearerAuth
//	@Accept			json
//	@Produce		json
//	@Param			request	body		authsdk.TOTPVerifyRequest	true	"TOTP code"
//	@Success		200		{object}	authsdk.BackupCodesResponse	"Backup codes (shown once)"
//	@Failure		400		{object}	authsdk.ErrorResponse		"Invalid TOTP code or request"
//	@Failure		401		{object}	authsdk.ErrorResponse		"Invalid or missing access token"
//	@Failure		500		{object}	authsdk.ErrorResponse		"Internal server error"
//	@Router			/v1/mfa/totp/verify [post].
func (h *MFAHandler) HandleVerify(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := slogx.FromContext(ctx)

	// Get user ID from context
	userID, ok := ctx.Value(httpx.CtxKeyUserID).(string)
	if !ok || userID == "" {
		authsdk.ErrInvalidToken.WriteError(w)
		return
	}

	// Parse request body
	var req authsdk.TOTPVerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Warn("failed to parse request", "err", err)
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": "Invalid JSON body",
		})
		return
	}

	// Verify TOTP code
	backupCodes, err := h.MFAService.VerifyTOTP(ctx, userID, req.Code)
	if err != nil {
		if err == service.ErrInvalidTOTPCode {
			log.Warn("invalid TOTP code", "user_id", userID)
			httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{
				"error":             "invalid_code",
				"error_description": "Invalid TOTP code",
			})
			return
		}
		if err == service.ErrMFAAlreadyEnabled {
			log.Warn("MFA already enabled", "user_id", userID)
			httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{
				"error":             "mfa_already_enabled",
				"error_description": "MFA is already enabled for this user",
			})
			return
		}
		log.Error("failed to verify TOTP", "user_id", userID, "err", err)
		authsdk.ErrServerError.WriteError(w)
		return
	}

	httpx.NoCache(w)
	httpx.WriteJSON(w, http.StatusOK, authsdk.BackupCodesResponse{
		Codes: backupCodes,
	})
}

// HandleRegenerateBackupCodes handles POST /v1/mfa/backup-codes
//
//	@Summary		Regenerate backup codes
//	@Description	Regenerates backup codes for the user. Requires TOTP verification.
//	@Tags			MFA
//	@Security		BearerAuth
//	@Accept			json
//	@Produce		json
//	@Param			request	body		authsdk.BackupCodesRegenerateRequest	true	"TOTP code for verification"
//	@Success		200		{object}	authsdk.BackupCodesResponse				"New backup codes (shown once)"
//	@Failure		400		{object}	authsdk.ErrorResponse					"Invalid TOTP code or request"
//	@Failure		401		{object}	authsdk.ErrorResponse					"Invalid or missing access token"
//	@Failure		500		{object}	authsdk.ErrorResponse					"Internal server error"
//	@Router			/v1/mfa/backup-codes [post].
func (h *MFAHandler) HandleRegenerateBackupCodes(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := slogx.FromContext(ctx)

	// Get user ID from context
	userID, ok := ctx.Value(httpx.CtxKeyUserID).(string)
	if !ok || userID == "" {
		authsdk.ErrInvalidToken.WriteError(w)
		return
	}

	// Parse request body
	var req authsdk.BackupCodesRegenerateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Warn("failed to parse request", "err", err)
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": "Invalid JSON body",
		})
		return
	}

	// Regenerate backup codes
	backupCodes, err := h.MFAService.RegenerateBackupCodes(ctx, userID, req.Code)
	if err != nil {
		if err == service.ErrInvalidTOTPCode {
			log.Warn("invalid TOTP code", "user_id", userID)
			httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{
				"error":             "invalid_code",
				"error_description": "Invalid TOTP code",
			})
			return
		}
		if err == service.ErrMFANotEnabled {
			log.Warn("MFA not enabled", "user_id", userID)
			httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{
				"error":             "mfa_not_enabled",
				"error_description": "MFA is not enabled for this user",
			})
			return
		}
		log.Error("failed to regenerate backup codes", "user_id", userID, "err", err)
		authsdk.ErrServerError.WriteError(w)
		return
	}

	httpx.NoCache(w)
	httpx.WriteJSON(w, http.StatusOK, authsdk.BackupCodesResponse{
		Codes: backupCodes,
	})
}

// HandleRemove handles DELETE /v1/mfa/totp
//
//	@Summary		Remove TOTP MFA
//	@Description	Removes TOTP MFA for the user. Requires TOTP verification.
//	@Tags			MFA
//	@Security		BearerAuth
//	@Accept			json
//	@Produce		json
//	@Param			request	body		authsdk.TOTPRemoveRequest	true	"TOTP code for verification"
//	@Success		200		{object}	map[string]string			"Success message"
//	@Failure		400		{object}	authsdk.ErrorResponse		"Invalid TOTP code or request"
//	@Failure		401		{object}	authsdk.ErrorResponse		"Invalid or missing access token"
//	@Failure		500		{object}	authsdk.ErrorResponse		"Internal server error"
//	@Router			/v1/mfa/totp [delete].
func (h *MFAHandler) HandleRemove(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := slogx.FromContext(ctx)

	// Get user ID from context
	userID, ok := ctx.Value(httpx.CtxKeyUserID).(string)
	if !ok || userID == "" {
		authsdk.ErrInvalidToken.WriteError(w)
		return
	}

	// Parse request body
	var req authsdk.TOTPRemoveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Warn("failed to parse request", "err", err)
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": "Invalid JSON body",
		})
		return
	}

	// Remove MFA
	err := h.MFAService.RemoveMFA(ctx, userID, req.Code)
	if err != nil {
		if err == service.ErrInvalidTOTPCode {
			log.Warn("invalid TOTP code", "user_id", userID)
			httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{
				"error":             "invalid_code",
				"error_description": "Invalid TOTP code",
			})
			return
		}
		if err == service.ErrMFANotEnabled {
			log.Warn("MFA not enabled", "user_id", userID)
			httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{
				"error":             "mfa_not_enabled",
				"error_description": "MFA is not enabled for this user",
			})
			return
		}
		log.Error("failed to remove MFA", "user_id", userID, "err", err)
		authsdk.ErrServerError.WriteError(w)
		return
	}

	httpx.NoCache(w)
	httpx.WriteJSON(w, http.StatusOK, map[string]string{
		"message": "MFA removed successfully",
	})
}
