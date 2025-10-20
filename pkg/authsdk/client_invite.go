package authsdk

import (
	"context"
	"net/http"
	"net/url"
	"strings"
)

// RedeemInvite redeems an invite token to create a new user account.
// This is a public endpoint (no authentication required).
func (c *SDKClient) RedeemInvite(
	ctx context.Context,
	req RedeemInviteRequest,
) (*RedeemInviteResponse, error) {
	// Encode as URL form data
	formData := url.Values{}
	formData.Set("invite_token", req.InviteToken)
	formData.Set("username", req.Username)
	formData.Set("password", req.Password)
	formData.Set("client_id", req.ClientID)

	headers := map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
	}

	resp, err := c.doRequest(
		ctx,
		http.MethodPost,
		"/v1/invites/redeem",
		strings.NewReader(formData.Encode()),
		headers,
	)
	if err != nil {
		return nil, err
	}

	var redeemResp RedeemInviteResponse
	if err := decodeJSON(resp, &redeemResp, http.StatusOK); err != nil {
		return nil, err
	}

	return &redeemResp, nil
}
