package main

import (
	"crypto/subtle"
	"net/http"
	"strings"
)

const labTokenHeader = "X-Alchemist-Lab-Token"

// withLabAuthorization protects every lab route, including read-only artifact
// downloads. The lab service controls Docker through the host socket, so an
// unset token disables its HTTP surface instead of silently exposing it.
func withLabAuthorization(next http.Handler, configuredToken string) http.Handler {
	token := strings.TrimSpace(configuredToken)
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if !strings.HasPrefix(request.URL.Path, "/api/v1/labs") {
			next.ServeHTTP(response, request)
			return
		}
		if token == "" {
			http.Error(response, "lab API is disabled", http.StatusServiceUnavailable)
			return
		}
		provided := request.Header.Get(labTokenHeader)
		if len(provided) != len(token) || subtle.ConstantTimeCompare([]byte(provided), []byte(token)) != 1 {
			http.Error(response, "lab API authorization required", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(response, request)
	})
}
