package core

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stephnangue/warden/auth/token"
	"github.com/stephnangue/warden/authorize"
	"github.com/stephnangue/warden/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthenticationMiddleware_Success(t *testing.T) {
	log := logger.NewZerologLogger(logger.DefaultConfig())
	tokenStore, _ := token.NewRobustStore(log, nil)
	defer tokenStore.Close()

	core := &Core{
		tokenStore: tokenStore,
		logger:     log,
	}

	backend := &SystemBackend{
		core:   core,
		logger: log,
	}

	// Generate WARDEN_TOKEN
	authData := &token.AuthData{
		PrincipalID:  "test-principal",
		RoleName:     "system_admin",
		AuthDeadline: time.Now().Add(10 * time.Minute),
		ExpireAt:     time.Now().Add(1 * time.Hour),
		RequestContext: map[string]string{
			"client_ip": "127.0.0.1",
		},
	}
	tok, err := tokenStore.GenerateToken(token.WARDEN_TOKEN, authData)
	require.NoError(t, err)

	// Test handler
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principalID := r.Context().Value(SystemPrincipalIDKey)
		assert.Equal(t, "test-principal", principalID)
		w.WriteHeader(http.StatusOK)
	})

	handler := backend.AuthenticationMiddleware(testHandler)

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+tok.Data["token"])
	req.Header.Set("X-Real-IP", "127.0.0.1") // Simulate Chi's RealIP middleware
	req.RemoteAddr = "127.0.0.1:12345"
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAuthenticationMiddleware_MissingToken(t *testing.T) {
	log := logger.NewZerologLogger(logger.DefaultConfig())
	backend := &SystemBackend{
		core:   &Core{logger: log},
		logger: log,
	}

	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not reach handler")
	})

	handler := backend.AuthenticationMiddleware(testHandler)

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthenticationMiddleware_InvalidToken(t *testing.T) {
	log := logger.NewZerologLogger(logger.DefaultConfig())
	tokenStore, _ := token.NewRobustStore(log, nil)
	defer tokenStore.Close()

	core := &Core{
		tokenStore: tokenStore,
		logger:     log,
	}

	backend := &SystemBackend{
		core:   core,
		logger: log,
	}

	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not reach handler")
	})

	handler := backend.AuthenticationMiddleware(testHandler)

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	req.Header.Set("X-Real-IP", "127.0.0.1") // Simulate Chi's RealIP middleware
	req.RemoteAddr = "127.0.0.1:12345"
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestCheckSystemAdmin_Success(t *testing.T) {
	log := logger.NewZerologLogger(logger.DefaultConfig())
	accessControl := authorize.NewAccessControl()
	accessControl.AssignRole("admin-user", "system_admin")

	core := &Core{
		accessControl: accessControl,
		logger:        log,
	}

	handlers := &SystemHandlers{
		core:   core,
		logger: log,
	}

	ctx := context.Background()
	ctx = context.WithValue(ctx, SystemPrincipalIDKey, "admin-user")
	ctx = context.WithValue(ctx, SystemRoleNameKey, "system_admin")

	err := handlers.checkSystemAdmin(ctx)

	assert.NoError(t, err)
}

func TestCheckSystemAdmin_Forbidden(t *testing.T) {
	log := logger.NewZerologLogger(logger.DefaultConfig())
	accessControl := authorize.NewAccessControl()

	core := &Core{
		accessControl: accessControl,
		logger:        log,
	}

	handlers := &SystemHandlers{
		core:   core,
		logger: log,
	}

	ctx := context.Background()
	ctx = context.WithValue(ctx, SystemPrincipalIDKey, "regular-user")
	ctx = context.WithValue(ctx, SystemRoleNameKey, "market_reader")

	err := handlers.checkSystemAdmin(ctx)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "insufficient permissions")
}
