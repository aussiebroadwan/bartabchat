package authsdk

import (
	"context"
	"net/http"
)

// GetJWKS retrieves the JSON Web Key Set for token verification.
func (c *SDKClient) GetJWKS(ctx context.Context) (*JWKSResponse, error) {
	resp, err := c.doRequest(ctx, http.MethodGet, "/.well-known/jwks.json", nil, nil)
	if err != nil {
		return nil, err
	}

	var jwks JWKSResponse
	if err := decodeJSON(resp, &jwks, http.StatusOK); err != nil {
		return nil, err
	}

	return &jwks, nil
}
