package http

import (
	"net/http"

	"github.com/aussiebroadwan/bartab/pkg/authsdk"
	"github.com/aussiebroadwan/bartab/pkg/httpx"
	"github.com/aussiebroadwan/bartab/pkg/jwtx"
)

// JWKSHandler exposes the JSON Web Key Set for public key discovery.
//
//	@Summary		Get JWKS
//	@Description	Returns the JSON Web Key Set used to verify JWTs.
//	@Tags			well-known
//	@Produce		json
//	@Success		200	{object}	authsdk.JWKSResponse	"The JSON Web Key Set"
//	@Router			/.well-known/jwks.json [get].
func JWKSHandler(keys *jwtx.KeySet) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		httpx.WriteJSON(w, http.StatusOK, authsdk.JWKSResponse(keys.PublicJWKS()))
	}
}
