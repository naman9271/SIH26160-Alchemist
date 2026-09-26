package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLabAuthorizationDoesNotAffectAnalysisRoutes(t *testing.T) {
	handler := withLabAuthorization(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusCreated)
	}), "secret")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/api/v1/analyses", nil))
	if response.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusCreated)
	}
}

func TestLabAuthorizationDisablesRoutesWithoutConfiguredToken(t *testing.T) {
	handler := withLabAuthorization(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("disabled lab route reached application handler")
	}), "")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/v1/labs/status", nil))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusServiceUnavailable)
	}
}

func TestLabAuthorizationRejectsWrongToken(t *testing.T) {
	handler := withLabAuthorization(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("unauthorized lab request reached application handler")
	}), "correct-token")
	request := httptest.NewRequest(http.MethodPost, "/api/v1/labs/activate", nil)
	request.Header.Set(labTokenHeader, "wrong-token")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusUnauthorized)
	}
}

func TestLabAuthorizationAcceptsExactToken(t *testing.T) {
	handler := withLabAuthorization(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusAccepted)
	}), "correct-token")
	request := httptest.NewRequest(http.MethodPost, "/api/v1/labs/activate", nil)
	request.Header.Set(labTokenHeader, "correct-token")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusAccepted)
	}
}
