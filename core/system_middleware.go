package core

import (
	"context"
	"net"
	"net/http"
	"strings"

	"github.com/stephnangue/warden/logger"
)

// Context keys for authenticated data
type systemContextKey string

const (
	SystemPrincipalIDKey systemContextKey = "system_principal_id"
	SystemRoleNameKey    systemContextKey = "system_role_name"
	SystemTokenKey       systemContextKey = "system_token"
)

// AuthenticationMiddleware validates Bearer tokens and extracts principal info
func (s *SystemBackend) AuthenticationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			s.logger.Warn("missing authorization header")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Parse Bearer token
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			s.logger.Warn("invalid authorization header format")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		tokenID := parts[1]

		
		// Use Chi's RealIP middleware result (should be set by router)
		clientIP := r.Header.Get("X-Real-IP")
		if clientIP == "" {
			// Fallback if RealIP middleware wasn't applied
			clientIP = r.RemoteAddr
		}
	
		// Remove port if present
		if host, _, err := net.SplitHostPort(clientIP); err == nil {
			clientIP = host
		}

		// Resolve token using Core's TokenStore
		principalID, roleName, err := s.core.tokenStore.ResolveToken(
			r.Context(),
			tokenID,
			map[string]string{
				"client_ip": clientIP,
			},
		)
		if err != nil {
			s.logger.Warn("token resolution failed",
				logger.Err(err),
				logger.String("token_id", tokenID))
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Get token object for metadata
		token := s.core.tokenStore.GetToken(tokenID)

		// Store authenticated data in context
		ctx := context.WithValue(r.Context(), SystemPrincipalIDKey, principalID)
		ctx = context.WithValue(ctx, SystemRoleNameKey, roleName)
		ctx = context.WithValue(ctx, SystemTokenKey, token)

		// Continue with authenticated context
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
