package core

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/openbao/openbao/helper/namespace"
	"github.com/stephnangue/warden/authorize"
	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthenticationMiddleware_Success(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	core := createTestCore(t)

	backend := &SystemBackend{
		core:   core,
		logger: log,
	}

	// Generate WARDEN_TOKEN
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)
	authData := &logical.AuthData{
		PrincipalID:  "test-principal",
		RoleName:     "system_admin",
		AuthDeadline: time.Now().Add(10 * time.Minute),
		ExpireAt:     time.Now().Add(1 * time.Hour),
		RequestContext: map[string]string{
			"client_ip": "127.0.0.1",
		},
	}
	tok, err := core.tokenStore.GenerateToken(ctx, "warden_token", authData)
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

	// Add namespace and client_ip to request context (normally done by ServeHTTP in request_handler.go)
	reqCtx := namespace.ContextWithNamespace(req.Context(), namespace.RootNamespace)
	reqCtx = context.WithValue(reqCtx, "client_ip", "127.0.0.1")
	req = req.WithContext(reqCtx)

	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAuthenticationMiddleware_MissingToken(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
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
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	core := createTestCore(t)

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

	// Add namespace and client_ip to request context (normally done by ServeHTTP in request_handler.go)
	reqCtx := namespace.ContextWithNamespace(req.Context(), namespace.RootNamespace)
	reqCtx = context.WithValue(reqCtx, "client_ip", "127.0.0.1")
	req = req.WithContext(reqCtx)

	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestCheckSystemAdmin_Success(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
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
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
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
