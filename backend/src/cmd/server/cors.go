package main

import (
	"net/http"
	"os"
	"strconv"
	"strings"
)

type corsConfig struct {
	allowedOrigins   map[string]struct{}
	allowAnyOrigin   bool
	allowedMethods   string
	allowedHeaders   string
	exposedHeaders   string
	allowCredentials bool
	maxAge           string
}

func corsConfigFromEnv() corsConfig {
	config := corsConfig{
		allowedOrigins: map[string]struct{}{},
		allowedMethods: envOrDefault("CORS_ALLOWED_METHODS", "GET,POST,OPTIONS"),
		allowedHeaders: envOrDefault("CORS_ALLOWED_HEADERS", "Authorization,Content-Type,X-Requested-With"),
		exposedHeaders: envOrDefault("CORS_EXPOSED_HEADERS", "Content-Disposition,Content-Type"),
		maxAge:         envOrDefault("CORS_MAX_AGE", "600"),
	}
	for _, value := range strings.Split(os.Getenv("CORS_ALLOWED_ORIGINS"), ",") {
		origin := strings.TrimSpace(strings.TrimRight(value, "/"))
		if origin == "" {
			continue
		}
		if origin == "*" {
			config.allowAnyOrigin = true
			continue
		}
		config.allowedOrigins[origin] = struct{}{}
	}
	config.allowCredentials, _ = strconv.ParseBool(os.Getenv("CORS_ALLOW_CREDENTIALS"))
	// Browsers reject the wildcard origin when credentials are enabled. Echoing
	// arbitrary origins here would turn a configuration error into open CORS.
	if config.allowAnyOrigin && config.allowCredentials {
		config.allowAnyOrigin = false
	}
	return config
}

func withCORS(next http.Handler, config corsConfig) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		origin := strings.TrimRight(strings.TrimSpace(request.Header.Get("Origin")), "/")
		if origin == "" {
			next.ServeHTTP(response, request)
			return
		}

		response.Header().Add("Vary", "Origin")
		response.Header().Add("Vary", "Access-Control-Request-Method")
		response.Header().Add("Vary", "Access-Control-Request-Headers")
		_, explicitlyAllowed := config.allowedOrigins[origin]
		if !config.allowAnyOrigin && !explicitlyAllowed {
			if request.Method == http.MethodOptions {
				http.Error(response, "origin is not allowed", http.StatusForbidden)
				return
			}
			next.ServeHTTP(response, request)
			return
		}

		allowedOrigin := origin
		if config.allowAnyOrigin {
			allowedOrigin = "*"
		}
		response.Header().Set("Access-Control-Allow-Origin", allowedOrigin)
		response.Header().Set("Access-Control-Expose-Headers", config.exposedHeaders)
		if config.allowCredentials {
			response.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		if request.Method == http.MethodOptions {
			response.Header().Set("Access-Control-Allow-Methods", config.allowedMethods)
			response.Header().Set("Access-Control-Allow-Headers", config.allowedHeaders)
			response.Header().Set("Access-Control-Max-Age", config.maxAge)
			response.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(response, request)
	})
}
