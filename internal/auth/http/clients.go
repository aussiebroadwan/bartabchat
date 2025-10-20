package http

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/aussiebroadwan/bartab/internal/auth/service"
	"github.com/aussiebroadwan/bartab/pkg/authsdk"
	"github.com/aussiebroadwan/bartab/pkg/httpx"
	"github.com/aussiebroadwan/bartab/pkg/slogx"
)

// ClientsHandler handles all client management endpoints.
type ClientsHandler struct {
	ClientService *service.ClientService
}

// HandleCreate handles POST /v1/clients
//
//	@Summary		Create OAuth2 Client
//	@Description	Creates a new OAuth2 client. If confidential=true, auto-generates a secret for client_credentials grant.
//	@Tags			Clients
//	@Accept			json
//	@Produce		json
//	@Security		BearerAuth
//	@Param			Authorization	header		string							true	"Bearer token with admin:write scope"
//	@Param			request			body		authsdk.CreateClientRequest		true	"Client creation request"
//	@Success		201				{object}	authsdk.CreateClientResponse	"client_id and client_secret (if confidential)"
//	@Failure		400				{object}	authsdk.ErrorResponse			"error, error_description"
//	@Failure		401				{object}	authsdk.ErrorResponse			"error, error_description"
//	@Failure		403				{object}	authsdk.ErrorResponse			"error, error_description"
//	@Failure		500				{object}	authsdk.ErrorResponse			"error, error_description"
//	@Router			/v1/clients [post].
func (h *ClientsHandler) HandleCreate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := slogx.FromContext(ctx)

	// Parse request body
	var req authsdk.CreateClientRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, authsdk.ErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "Invalid JSON in request body",
		})
		return
	}

	// Validate request
	if strings.TrimSpace(req.Name) == "" {
		httpx.WriteJSON(w, http.StatusBadRequest, authsdk.ErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "Client name is required",
		})
		return
	}

	if len(req.Scopes) == 0 {
		httpx.WriteJSON(w, http.StatusBadRequest, authsdk.ErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "At least one scope is required",
		})
		return
	}

	// Create the client
	clientID, secret, err := h.ClientService.CreateClient(
		ctx,
		req.Name,
		req.Confidential,
		req.Scopes,
	)
	if err != nil {
		log.Error("failed to create client", "error", err)
		httpx.WriteJSON(w, http.StatusInternalServerError, authsdk.ErrorResponse{
			Error:            "server_error",
			ErrorDescription: "Failed to create client",
		})
		return
	}

	// Return response (secret is only returned once at creation time)
	response := authsdk.CreateClientResponse{
		ClientID:     clientID,
		ClientSecret: secret, // Will be empty string if no secret was provided
	}

	httpx.WriteJSON(w, http.StatusCreated, response)
}

// HandleList handles GET /v1/clients
//
//	@Summary		List OAuth2 Clients
//	@Description	Returns all OAuth2 clients. Protected clients are flagged.
//	@Tags			Clients
//	@Produce		json
//	@Security		BearerAuth
//	@Param			Authorization	header		string						true	"Bearer token with admin:read scope"
//	@Success		200				{object}	authsdk.ListClientsResponse	"List of clients"
//	@Failure		401				{object}	authsdk.ErrorResponse		"error, error_description"
//	@Failure		403				{object}	authsdk.ErrorResponse		"error, error_description"
//	@Failure		500				{object}	authsdk.ErrorResponse		"error, error_description"
//	@Router			/v1/clients [get].
func (h *ClientsHandler) HandleList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := slogx.FromContext(ctx)

	// Get all clients
	clients, err := h.ClientService.ListClients(ctx)
	if err != nil {
		log.Error("failed to list clients", "error", err)
		httpx.WriteJSON(w, http.StatusInternalServerError, authsdk.ErrorResponse{
			Error:            "server_error",
			ErrorDescription: "Failed to list clients",
		})
		return
	}

	// Convert to response format
	clientResponses := make([]authsdk.ClientInfo, len(clients))
	for i, client := range clients {
		clientResponses[i] = authsdk.ClientInfo{
			ID:        client.ID,
			Name:      client.Name,
			Scopes:    client.Scopes,
			HasSecret: client.SecretHash != "",
			Protected: client.Protected,
			CreatedAt: client.CreatedAt.Format(time.RFC3339),
		}
	}

	response := authsdk.ListClientsResponse{
		Clients: clientResponses,
	}

	httpx.WriteJSON(w, http.StatusOK, response)
}

// HandleDelete handles DELETE /v1/clients/:id
//
//	@Summary		Delete OAuth2 Client
//	@Description	Deletes an OAuth2 client by ID. Protected clients cannot be deleted.
//	@Tags			Clients
//	@Produce		json
//	@Security		BearerAuth
//	@Param			Authorization	header	string	true	"Bearer token with admin:write scope"
//	@Param			id				path	string	true	"Client ID (ULID)"
//	@Success		204				"Client deleted successfully"
//	@Failure		400				{object}	authsdk.ErrorResponse	"error, error_description"
//	@Failure		401				{object}	authsdk.ErrorResponse	"error, error_description"
//	@Failure		403				{object}	authsdk.ErrorResponse	"error, error_description"
//	@Failure		404				{object}	authsdk.ErrorResponse	"error, error_description"
//	@Failure		500				{object}	authsdk.ErrorResponse	"error, error_description"
//	@Router			/v1/clients/{id} [delete].
func (h *ClientsHandler) HandleDelete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := slogx.FromContext(ctx)

	// Extract client ID from URL path
	clientID := r.PathValue("id")

	// Delete the client
	err := h.ClientService.DeleteClient(ctx, clientID)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrClientNotFound):
			httpx.WriteJSON(w, http.StatusNotFound, authsdk.ErrorResponse{
				Error:            "client_not_found",
				ErrorDescription: "Client not found",
			})
		case errors.Is(err, service.ErrClientProtected):
			httpx.WriteJSON(w, http.StatusForbidden, authsdk.ErrorResponse{
				Error:            "client_protected",
				ErrorDescription: "Cannot delete protected client",
			})
		default:
			log.Error("failed to delete client", "error", err, "client_id", clientID)
			httpx.WriteJSON(w, http.StatusInternalServerError, authsdk.ErrorResponse{
				Error:            "server_error",
				ErrorDescription: "Failed to delete client",
			})
		}
		return
	}

	// Return 204 No Content on success
	w.WriteHeader(http.StatusNoContent)
}
