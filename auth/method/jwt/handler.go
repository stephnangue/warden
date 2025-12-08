package jwt

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"time"

	"github.com/hashicorp/cap/jwt"
	"github.com/stephnangue/warden/audit"
	"github.com/stephnangue/warden/auth/token"
	"github.com/stephnangue/warden/helper"
	"github.com/stephnangue/warden/logger"
)

func (m *JWTAuthMethod) HandleRequest(w http.ResponseWriter, r *http.Request) error {
	// Check if auth method has been configured
	if m.config == nil  {
		http.Error(w, "Auth method not configured", http.StatusServiceUnavailable)
		return nil
	}

	m.router.ServeHTTP(w, r)

	return nil
}

func (m *JWTAuthMethod) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Body == nil {
		m.auditResponse(w, r, nil, nil, nil, nil, http.StatusBadRequest, "No request body provided", "no request body provided")
		http.Error(w, "No request body provided", http.StatusBadRequest)
		return
	}

	var logRequest JWTLoginRequest
	err := json.NewDecoder(r.Body).Decode(&logRequest)
	if err != nil {
		m.auditResponse(w, r, nil, nil, nil, nil, http.StatusBadRequest, "Bad request", err.Error())
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	role, exist := m.roles.GetRole(logRequest.Role)
	if !exist {
		m.auditResponse(w, r, &logRequest, nil, nil, nil, http.StatusUnauthorized, "Unauthorized", "the role does not exist")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// 1. Perform the authentication and fetch the principal
	ctx := context.Background()
	expected := jwt.Expected{
		SigningAlgorithms: []jwt.Alg{jwt.RS256, jwt.RS384, jwt.RS512, jwt.ES256, jwt.ES384, jwt.ES512},
	}
	if m.config.BoundIssuer != "" {
		expected.Issuer = m.config.BoundIssuer
	}
	if m.config.BoundSubject != "" {
		expected.Subject = m.config.BoundSubject
	}
	if len(m.config.BoundAudiences) > 0 {
		expected.Audiences = m.config.BoundAudiences
	}

	claims, err := m.config.validator.Validate(ctx, logRequest.JWT, expected)
	if err != nil {
		// JWT validation failed
		m.auditResponse(w, r, &logRequest, nil, nil, nil, http.StatusUnauthorized, "Unauthorized", err.Error())
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Validate bound claims
	if err := validateBoundClaims(claims, m.config.BoundClaims); err != nil {
		// failed to validate claims
		m.auditResponse(w, r, &logRequest, nil, nil, nil, http.StatusUnauthorized, "Unauthorized", err.Error())
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Extract principal identity
	principalID := extractClaim(claims, m.config.UserClaim)
	if principalID == "" {
		m.auditResponse(w, r, &logRequest, nil, nil, nil, http.StatusUnauthorized, "Unauthorized", "no principal identity found in the jwt")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Extract issue
	tokenIssuer := extractClaim(claims, "iss")
	if tokenIssuer == "" {
		m.auditResponse(w, r, &logRequest, nil, nil, nil, http.StatusUnauthorized, "Unauthorized", "no issuer found in the jwt")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Extract token ID
	tokenID := extractClaim(claims, "jti")
	if tokenID == "" {
		m.auditResponse(w, r, &logRequest, nil, nil, nil, http.StatusUnauthorized, "Unauthorized", "no JWT ID found in the jwt")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Extract expiration time
	expValue, ok := claims["exp"]
	if !ok {
		m.auditResponse(w, r, &logRequest, nil, nil, nil, http.StatusUnauthorized, "Unauthorized", "no exp found in the jwt")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Parse expiration time and calculate TTL
	var expTimestamp int64
	switch v := expValue.(type) {
	case float64:
		expTimestamp = int64(v)
	case int64:
		expTimestamp = v
	case int:
		expTimestamp = int64(v)
	default:
		m.auditResponse(w, r, &logRequest, nil, nil, nil, http.StatusUnauthorized, "Unauthorized", "invalid exp format in the jwt")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	jwtExpiration := time.Unix(expTimestamp, 0)
	tokenTTL := time.Until(jwtExpiration).Seconds()

	// Ensure TTL is positive
	if tokenTTL <= 0 {
		m.auditResponse(w, r, &logRequest, nil, nil, nil, http.StatusUnauthorized, "Unauthorized", "jwt has expired")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	clientToken := audit.Token{
		Type:        "bearer",
		TokenID:     tokenID,
		TokenTTL:    int64(tokenTTL),
		TokenIssuer: tokenIssuer,
		Data: map[string]string{
			"jwt": logRequest.JWT,
		},
	}

	// 2. Check if the principal is allowed to assume the role
	if !m.accessControl.IsAllowed(principalID, logRequest.Role) {
		m.auditResponse(w, r, &logRequest, &clientToken, nil, nil, http.StatusForbidden, "Permission denied", "the principal is not allowed to assume the role")
		http.Error(w, "Permission denied", http.StatusForbidden)
		return
	}

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

	// 3. Generate and return the token
	switch role.Type {
	case "static_database_userpass", "dynamic_database_userpass":
		now := time.Now()
		authData := token.AuthData{
			PrincipalID:  principalID,
			RoleName:     role.Name,
			AuthDeadline: now.Add(m.config.AuthDeadline),
			ExpireAt:     now.Add(m.config.TokenTTL),
			RequestContext: map[string]string{
				"client_ip": clientIP,
			},
		}
		tokenValue, err := m.tokenStore.GenerateToken(token.USER_PASS, &authData)

		if err != nil {
			// error when creating token
			m.logger.Error("Failed to generate token", logger.String("token_type", token.USER_PASS), logger.Any("auth_data", authData))
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		ok := m.auditResponse(w, r, &logRequest, &clientToken, tokenValue, &authData, http.StatusOK, "OK", "")
		if !ok {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		helper.JSONResponse(w, http.StatusOK, tokenValue.Data)
		return
	case "static_aws_access_keys", "dynamic_aws_access_keys":
		now := time.Now()
		authData := token.AuthData{
			PrincipalID:  principalID,
			RoleName:     role.Name,
			AuthDeadline: now.Add(m.config.AuthDeadline),
			ExpireAt:     now.Add(m.config.TokenTTL),
			RequestContext: map[string]string{
				"client_ip": clientIP,
			},
		}
		tokenValue, err := m.tokenStore.GenerateToken(token.AWS_ACCESS_KEYS, &authData)

		if err != nil {
			m.logger.Error("Failed to generate token", logger.String("token_type", token.AWS_ACCESS_KEYS), logger.Any("auth_data", authData))
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		ok := m.auditResponse(w, r, &logRequest, &clientToken, tokenValue, &authData, http.StatusOK, "OK", "")
		if !ok {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		helper.JSONResponse(w, http.StatusOK, tokenValue.Data)
		return
	case "system":
		now := time.Now()
		authData := token.AuthData{
			PrincipalID:  principalID,
			RoleName:     role.Name,
			AuthDeadline: now.Add(m.config.AuthDeadline),
			ExpireAt:     now.Add(m.config.TokenTTL),
			RequestContext: map[string]string{
				"client_ip": clientIP,
			},
		}
		tokenValue, err := m.tokenStore.GenerateToken(token.WARDEN_TOKEN, &authData)

		if err != nil {
			m.logger.Error("Failed to generate token", logger.String("token_type", token.WARDEN_TOKEN), logger.Any("auth_data", authData))
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		ok := m.auditResponse(w, r, &logRequest, &clientToken, tokenValue, &authData, http.StatusOK, "OK", "")
		if !ok {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		helper.JSONResponse(w, http.StatusOK, tokenValue.Data)
	default:
		m.logger.Warn("Unsupported role type", logger.String("role_type", role.Type))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
}



