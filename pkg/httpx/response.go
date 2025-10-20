package httpx

import (
	"encoding/json"
	"net/http"
	"strings"
)

// WriteJSON writes a JSON response with the given status code.
// It automatically sets the Content-Type header and Cache-Control headers.
func WriteJSON(w http.ResponseWriter, code int, v any) {
	NoCache(w)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// NoCache sets the Cache-Control and Pragma headers to prevent caching.
// This is commonly required for sensitive responses like tokens.
func NoCache(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
}

// ParseSpaceDelimitedFields splits a space-delimited string into fields.
// This is useful for parsing space-separated lists like scopes.
// Returns nil if the input string is empty or contains only whitespace.
func ParseSpaceDelimitedFields(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	return strings.Fields(s)
}
