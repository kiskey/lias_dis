// Package api implements the HTTP server, middleware, and SSE broker for DIS.
//
// File:    apps/discovery-service/internal/api/middleware.go
// Version: 1.0
package api

import (
    "net/http"
    "strings"
)

// AuthMiddleware enforces Bearer token authentication if a token is configured.
func AuthMiddleware(token string, next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if token == "" {
            next.ServeHTTP(w, r)
            return
        }

        authHeader := r.Header.Get("Authorization")
        if authHeader == "" {
            http.Error(w, `{"error":"missing authorization header"}`, http.StatusUnauthorized)
            return
        }

        parts := strings.SplitN(authHeader, " ", 2)
        if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || parts[1] != token {
            http.Error(w, `{"error":"invalid or malformed authorization token"}`, http.StatusUnauthorized)
            return
        }

        next.ServeHTTP(w, r)
    })
}
