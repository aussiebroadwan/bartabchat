package http

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/aussiebroadwan/bartab/internal/auth/domain"
	"github.com/aussiebroadwan/bartab/internal/auth/service"
	"github.com/aussiebroadwan/bartab/pkg/authsdk"
	"github.com/aussiebroadwan/bartab/pkg/httpx"
)

// KeyRotationHandler handles key rotation operations for both ephemeral and persistent modes.
// All endpoints require admin scopes (admin:write for mutations, admin:read for listing).
type KeyRotationHandler struct {
	KeyRotationService *service.KeyRotationService
}

// HandleRotate handles POST /v1/keys/rotate
//
//	@Summary		Rotate signing keys
//	@Description	Generate a new signing key and optionally retire existing keys (works in both ephemeral and persistent modes)
//	@Tags			Keys
//	@Accept			json
//	@Produce		json
//	@Param			body	body		authsdk.RotateKeyRequest	true	"Rotation options"
//	@Success		200		{object}	authsdk.RotateKeyResponse
//	@Failure		400		{object}	authsdk.ErrorResponse	"Bad Request"
//	@Failure		401		{object}	authsdk.ErrorResponse	"Unauthorized"
//	@Failure		403		{object}	authsdk.ErrorResponse	"Forbidden - requires admin:write scope"
//	@Failure		500		{object}	authsdk.ErrorResponse	"Internal Server Error"
//	@Security		BearerAuth
//	@Router			/v1/keys/rotate [post]
func (h *KeyRotationHandler) HandleRotate(w http.ResponseWriter, r *http.Request) {
	if h.KeyRotationService == nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, authsdk.ErrorResponse{
			Error:            "server_error",
			ErrorDescription: "Key rotation service not initialized",
		})
		return
	}

	var req authsdk.RotateKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, authsdk.ErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "Invalid request body",
		})
		return
	}

	resp, err := h.KeyRotationService.RotateKey(r.Context(), service.RotateKeyRequest{
		RetireExisting: req.RetireExisting,
	})
	if err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, authsdk.ErrorResponse{
			Error:            "server_error",
			ErrorDescription: err.Error(),
		})
		return
	}

	// Convert service response to authsdk response
	sdkResp := authsdk.RotateKeyResponse{
		NewKey:      domainToSDKKey(resp.NewKey),
		RetiredKeys: domainKeysToSDK(resp.RetiredKeys),
		ActiveKeys:  resp.ActiveKeys,
	}

	httpx.WriteJSON(w, http.StatusOK, sdkResp)
}

// HandleListKeys handles GET /v1/keys
//
//	@Summary		List signing keys
//	@Description	List all signing keys with their status (works in both ephemeral and persistent modes)
//	@Tags			Keys
//	@Produce		json
//	@Success		200	{array}		authsdk.SigningKeyInfo
//	@Failure		401	{object}	authsdk.ErrorResponse	"Unauthorized"
//	@Failure		403	{object}	authsdk.ErrorResponse	"Forbidden - requires admin:read scope"
//	@Failure		500	{object}	authsdk.ErrorResponse
//	@Failure		501	{object}	authsdk.ErrorResponse	"Not available in ephemeral mode"
//	@Security		BearerAuth
//	@Router			/v1/keys [get]
func (h *KeyRotationHandler) HandleListKeys(w http.ResponseWriter, r *http.Request) {
	if h.KeyRotationService == nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, authsdk.ErrorResponse{
			Error:            "server_error",
			ErrorDescription: "Key rotation service not initialized",
		})
		return
	}

	keys, err := h.KeyRotationService.ListSigningKeys(r.Context())
	if err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, authsdk.ErrorResponse{
			Error:            "server_error",
			ErrorDescription: err.Error(),
		})
		return
	}

	// Convert domain keys to SDK keys
	sdkKeys := domainKeysToSDK(keys)

	httpx.WriteJSON(w, http.StatusOK, sdkKeys)
}

// domainToSDKKey converts a domain.SigningKey to authsdk.SigningKeyInfo
func domainToSDKKey(key domain.SigningKey) authsdk.SigningKeyInfo {
	var retiredAt *string
	if key.RetiredAt != nil {
		str := key.RetiredAt.Format(time.RFC3339)
		retiredAt = &str
	}

	return authsdk.SigningKeyInfo{
		ID:        key.ID,
		Kid:       key.Kid,
		Algorithm: key.Algorithm,
		CreatedAt: key.CreatedAt.Format(time.RFC3339),
		RetiredAt: retiredAt,
		ExpiresAt: key.ExpiresAt.Format(time.RFC3339),
	}
}

// domainKeysToSDK converts a slice of domain.SigningKey to authsdk.SigningKeyInfo
func domainKeysToSDK(keys []domain.SigningKey) []authsdk.SigningKeyInfo {
	sdkKeys := make([]authsdk.SigningKeyInfo, len(keys))
	for i, key := range keys {
		sdkKeys[i] = domainToSDKKey(key)
	}
	return sdkKeys
}

// HandleRetireKey handles POST /v1/keys/{kid}/retire
//
//	@Summary		Retire a signing key
//	@Description	Mark a specific key as retired without generating a new one (works in both ephemeral and persistent modes)
//	@Tags			Keys
//	@Produce		json
//	@Param			kid	path	string	true	"Key ID to retire"
//	@Success		204	"No Content - key retired successfully"
//	@Failure		400	{object}	authsdk.ErrorResponse
//	@Failure		401	{object}	authsdk.ErrorResponse	"Unauthorized"
//	@Failure		403	{object}	authsdk.ErrorResponse	"Forbidden - requires admin:write scope"
//	@Failure		404	{object}	authsdk.ErrorResponse	"Key not found"
//	@Failure		500	{object}	authsdk.ErrorResponse
//	@Failure		501	{object}	authsdk.ErrorResponse	"Not available in ephemeral mode"
//	@Security		BearerAuth
//	@Router			/v1/keys/{kid}/retire [post]
func (h *KeyRotationHandler) HandleRetireKey(w http.ResponseWriter, r *http.Request) {
	if h.KeyRotationService == nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, authsdk.ErrorResponse{
			Error:            "server_error",
			ErrorDescription: "Key rotation service not initialized",
		})
		return
	}

	// Extract kid from path parameter
	kid := r.PathValue("kid")
	if kid == "" {
		httpx.WriteJSON(w, http.StatusBadRequest, authsdk.ErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "kid is required",
		})
		return
	}

	if err := h.KeyRotationService.RetireKey(r.Context(), kid); err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, authsdk.ErrorResponse{
			Error:            "server_error",
			ErrorDescription: err.Error(),
		})
		return
	}

	// Return 204 No Content on success
	w.WriteHeader(http.StatusNoContent)
}
