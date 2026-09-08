package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCORSAllowsConfiguredOrigin(t *testing.T) {
	config := corsConfig{
		allowedOrigins: map[string]struct{}{"https://dashboard.example.com": {}},
		allowedMethods: "GET,POST,OPTIONS", allowedHeaders: "Content-Type",
		exposedHeaders: "Content-Disposition", maxAge: "600",
	}
	handler := withCORS(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusOK)
	}), config)

	request := httptest.NewRequest(http.MethodOptions, "/api/v1/pcap", nil)
	request.Header.Set("Origin", "https://dashboard.example.com")
	request.Header.Set("Access-Control-Request-Method", http.MethodPost)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusNoContent)
	}
	if got := response.Header().Get("Access-Control-Allow-Origin"); got != "https://dashboard.example.com" {
		t.Fatalf("Access-Control-Allow-Origin = %q", got)
	}
}

func TestCORSRejectsUnknownPreflightOrigin(t *testing.T) {
	config := corsConfig{allowedOrigins: map[string]struct{}{"https://dashboard.example.com": {}}}
	handler := withCORS(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("disallowed preflight reached the application handler")
	}), config)

	request := httptest.NewRequest(http.MethodOptions, "/api/v1/pcap", nil)
	request.Header.Set("Origin", "https://attacker.example")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusForbidden)
	}
	if got := response.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("unexpected Access-Control-Allow-Origin = %q", got)
	}
}

func TestCORSLeavesSameOriginRequestsAlone(t *testing.T) {
	handler := withCORS(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusCreated)
	}), corsConfig{allowedOrigins: map[string]struct{}{}})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/api/v1/pcap", nil))
	if response.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusCreated)
	}
}
