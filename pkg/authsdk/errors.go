package authsdk

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/aussiebroadwan/bartab/pkg/httpx"
)

// ============================================================================
// OAuth2 Error Codes (RFC 6749)
// ============================================================================

const (
	// OAuth2 error codes per RFC 6749
	ErrorCodeInvalidRequest          = "invalid_request"
	ErrorCodeInvalidClient           = "invalid_client"
	ErrorCodeInvalidGrant            = "invalid_grant"
	ErrorCodeUnauthorizedClient      = "unauthorized_client"
	ErrorCodeUnsupportedGrantType    = "unsupported_grant_type"
	ErrorCodeInvalidScope            = "invalid_scope"
	ErrorCodeServerError             = "server_error"
	ErrorCodeInvalidToken            = "invalid_token"
	ErrorCodeMFARequired             = "mfa_required"
	ErrorCodeInsufficientScope       = "insufficient_scope"
	ErrorCodeAccessDenied            = "access_denied"
	ErrorCodeUnsupportedResponseType = "unsupported_response_type"
)

// ============================================================================
// OAuth2Error - Standard OAuth2 error type
// ============================================================================

// OAuth2Error represents a standard OAuth2 error response per RFC 6749.
// It implements the error interface and can be used both by the server
// (to write HTTP responses) and by the SDK client (to represent errors).
type OAuth2Error struct {
	// StatusCode is the HTTP status code for this error
	StatusCode int `json:"-"`

	// Code is the OAuth2 error code (e.g., "invalid_request", "invalid_grant")
	Code string `json:"error"`

	// Description is a human-readable description of the error
	Description string `json:"error_description"`
}

// Error implements the error interface.
func (e *OAuth2Error) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Description)
}

// WriteError writes this OAuth2Error to an HTTP response writer.
// This is used by HTTP handlers to return OAuth2-compliant error responses.
func (e *OAuth2Error) WriteError(w http.ResponseWriter) {
	httpx.NoCache(w)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(e.StatusCode)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             e.Code,
		"error_description": e.Description,
	})
}

// ============================================================================
// Predefined OAuth2 Errors
// ============================================================================

var (
	// ErrInvalidRequest is returned when the request is missing a required parameter,
	// includes an invalid parameter value, includes a parameter more than once,
	// or is otherwise malformed.
	ErrInvalidRequest = &OAuth2Error{
		StatusCode:  http.StatusBadRequest,
		Code:        ErrorCodeInvalidRequest,
		Description: "the request is malformed or missing required parameters",
	}

	// ErrInvalidClient is returned when client authentication failed.
	ErrInvalidClient = &OAuth2Error{
		StatusCode:  http.StatusUnauthorized,
		Code:        ErrorCodeInvalidClient,
		Description: "invalid client",
	}

	// ErrInvalidGrant is returned when the provided authorization grant
	// (e.g., authorization code, resource owner credentials) or refresh token
	// is invalid, expired, revoked, or was issued to another client.
	ErrInvalidGrant = &OAuth2Error{
		StatusCode:  http.StatusUnauthorized,
		Code:        ErrorCodeInvalidGrant,
		Description: "invalid credentials",
	}

	// ErrUnauthorizedClient is returned when the authenticated client is not
	// authorized to use this authorization grant type.
	ErrUnauthorizedClient = &OAuth2Error{
		StatusCode:  http.StatusBadRequest,
		Code:        ErrorCodeUnauthorizedClient,
		Description: "the client is not authorized to use this grant type",
	}

	// ErrUnsupportedGrantType is returned when the authorization grant type
	// is not supported by the authorization server.
	ErrUnsupportedGrantType = &OAuth2Error{
		StatusCode:  http.StatusBadRequest,
		Code:        ErrorCodeUnsupportedGrantType,
		Description: "grant type not supported",
	}

	// ErrInvalidScope is returned when the requested scope is invalid, unknown,
	// malformed, or exceeds the scope granted by the resource owner.
	ErrInvalidScope = &OAuth2Error{
		StatusCode:  http.StatusBadRequest,
		Code:        ErrorCodeInvalidScope,
		Description: "requested scope is invalid",
	}

	// ErrServerError is returned when the authorization server encountered an
	// unexpected condition that prevented it from fulfilling the request.
	ErrServerError = &OAuth2Error{
		StatusCode:  http.StatusInternalServerError,
		Code:        ErrorCodeServerError,
		Description: "internal server error",
	}

	// ErrMethodNotAllowed is returned when the HTTP method is not allowed.
	ErrMethodNotAllowed = &OAuth2Error{
		StatusCode:  http.StatusMethodNotAllowed,
		Code:        ErrorCodeInvalidRequest,
		Description: "method not allowed",
	}

	// ErrInvalidContentType is returned when the Content-Type header is not
	// application/x-www-form-urlencoded as required by OAuth2 spec.
	ErrInvalidContentType = &OAuth2Error{
		StatusCode:  http.StatusBadRequest,
		Code:        ErrorCodeInvalidRequest,
		Description: "content-type must be application/x-www-form-urlencoded",
	}

	// ErrInvalidFormBody is returned when the form body cannot be parsed.
	ErrInvalidFormBody = &OAuth2Error{
		StatusCode:  http.StatusBadRequest,
		Code:        ErrorCodeInvalidRequest,
		Description: "invalid form body",
	}

	// ErrInvalidToken is returned when the access token is missing, invalid, expired or revoked.
	ErrInvalidToken = &OAuth2Error{
		StatusCode:  http.StatusUnauthorized,
		Code:        ErrorCodeInvalidToken,
		Description: "the access token is missing, invalid, expired or revoked",
	}

	// ErrInsufficientScope is returned when the access token lacks required scopes.
	ErrInsufficientScope = &OAuth2Error{
		StatusCode:  http.StatusForbidden,
		Code:        ErrorCodeInsufficientScope,
		Description: "the access token does not have the required scopes",
	}

	// ErrAccessDenied is returned when the resource owner or authorization server denied the request.
	ErrAccessDenied = &OAuth2Error{
		StatusCode:  http.StatusForbidden,
		Code:        ErrorCodeAccessDenied,
		Description: "access denied",
	}

	// ErrUnsupportedResponseType is returned when the authorization server does not support
	// obtaining an authorization code using this method.
	ErrUnsupportedResponseType = &OAuth2Error{
		StatusCode:  http.StatusBadRequest,
		Code:        ErrorCodeUnsupportedResponseType,
		Description: "response type not supported",
	}
)

// NewOAuth2Error creates a new OAuth2Error with the given status code, error code, and description.
// This is useful when you need to create custom error messages while maintaining OAuth2 compliance.
func NewOAuth2Error(statusCode int, code, description string) *OAuth2Error {
	return &OAuth2Error{
		StatusCode:  statusCode,
		Code:        code,
		Description: description,
	}
}

// ============================================================================
// MFA Error Response
// ============================================================================

// MFARequiredError is returned when MFA is required to complete authentication.
// It's returned with HTTP 409 Conflict because the request is valid but conflicts
// with the user's current state (MFA-enabled) which requires additional authentication steps.
type MFARequiredError struct {
	// MFAToken is the token to use when submitting the MFA response
	MFAToken string `json:"mfa_token"`

	// Methods lists the available MFA methods (e.g., ["totp", "backup_codes"])
	Methods []string `json:"mfa_methods"`
}

// Error implements the error interface.
func (e *MFARequiredError) Error() string {
	return fmt.Sprintf("MFA required: available methods=%v", e.Methods)
}

// WriteError writes the MFA required error as a 409 Conflict with OAuth2 error format.
func (e *MFARequiredError) WriteError(w http.ResponseWriter) {
	httpx.NoCache(w)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusConflict) // 409
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error":             ErrorCodeMFARequired,
		"error_description": "Multi-factor authentication is required to complete this request",
		"mfa_token":         e.MFAToken,
		"mfa_methods":       e.Methods,
	})
}

// ============================================================================
// Error Parsing Helpers
// ============================================================================

// parseErrorResponse attempts to parse an HTTP error response into a typed error.
// It checks for MFA challenges (409), OAuth2 errors, and validation errors.
// Returns nil if the response indicates success (2xx status code).
func parseErrorResponse(resp *http.Response, body []byte) error {
	// Success responses
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}

	// Check for MFA challenge (409 Conflict)
	if resp.StatusCode == http.StatusConflict {
		var mfaResp struct {
			Error            string   `json:"error"`
			ErrorDescription string   `json:"error_description"`
			MFAToken         string   `json:"mfa_token"`
			MFAMethods       []string `json:"mfa_methods"`
		}
		if err := json.Unmarshal(body, &mfaResp); err == nil {
			if mfaResp.Error == ErrorCodeMFARequired && mfaResp.MFAToken != "" {
				return &MFARequiredError{
					MFAToken: mfaResp.MFAToken,
					Methods:  mfaResp.MFAMethods,
				}
			}
		}
	}

	// Try parsing as standard OAuth2 error
	var errResp ErrorResponse
	if err := json.Unmarshal(body, &errResp); err == nil && errResp.Error != "" {
		return &OAuth2Error{
			StatusCode:  resp.StatusCode,
			Code:        errResp.Error,
			Description: errResp.ErrorDescription,
		}
	}

	// Try parsing as validation error
	var valErr ValidationErrorResponse
	if err := json.Unmarshal(body, &valErr); err == nil && valErr.Code != "" {
		return &OAuth2Error{
			StatusCode:  resp.StatusCode,
			Code:        valErr.Code,
			Description: valErr.Message,
		}
	}

	// Fallback: create generic error from status code
	return &OAuth2Error{
		StatusCode:  resp.StatusCode,
		Code:        ErrorCodeServerError,
		Description: fmt.Sprintf("HTTP %d: %s", resp.StatusCode, http.StatusText(resp.StatusCode)),
	}
}
