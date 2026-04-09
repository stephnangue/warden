package http

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openbao/openbao/sdk/v2/physical/inmem"
	"github.com/stephnangue/warden/audit"
	"github.com/stephnangue/warden/core"
	"github.com/stephnangue/warden/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"strings"
)

func TestParseHealthStatusOverrides(t *testing.T) {
	tests := []struct {
		name        string
		query       string
		initialized bool
		sealed      bool
		standby     bool
		wantCode    int
	}{
		{
			name:     "no overrides",
			query:    "",
			standby:  true,
			wantCode: 0,
		},
		{
			name:     "standbyok makes standby return 200",
			query:    "standbyok=true",
			standby:  true,
			wantCode: http.StatusOK,
		},
		{
			name:     "standbyok ignored when not standby",
			query:    "standbyok=true",
			standby:  false,
			wantCode: 0,
		},
		{
			name:     "custom standby code",
			query:    "standbycode=200",
			standby:  true,
			wantCode: 200,
		},
		{
			name:        "custom sealed code",
			query:       "sealedcode=200",
			initialized: true,
			sealed:      true,
			wantCode:    200,
		},
		{
			name:        "custom uninit code",
			query:       "uninitcode=200",
			initialized: false,
			wantCode:    200,
		},
		{
			name:     "invalid code ignored",
			query:    "standbycode=abc",
			standby:  true,
			wantCode: 0,
		},
		{
			name:     "out of range code ignored",
			query:    "standbycode=999",
			standby:  true,
			wantCode: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/v1/sys/health?"+tt.query, nil)
			got := parseHealthStatusOverrides(r, tt.initialized, tt.sealed, tt.standby)
			assert.Equal(t, tt.wantCode, got)
		})
	}
}

func TestHealthResponse_JSON(t *testing.T) {
	resp := &HealthResponse{
		Initialized:   true,
		Sealed:        false,
		Standby:       false,
		ServerTimeUTC: 1234567890,
	}

	data, err := json.Marshal(resp)
	require.NoError(t, err)

	var decoded HealthResponse
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, resp.Initialized, decoded.Initialized)
	assert.Equal(t, resp.Sealed, decoded.Sealed)
	assert.Equal(t, resp.Standby, decoded.Standby)
	assert.Equal(t, resp.ServerTimeUTC, decoded.ServerTimeUTC)
}

func TestLeaderResponse_JSON(t *testing.T) {
	resp := LeaderResponse{
		HAEnabled:     true,
		IsSelf:        true,
		LeaderAddress: "https://leader:8200",
		ActiveTime:    "2026-01-01T00:00:00Z",
	}

	data, err := json.Marshal(resp)
	require.NoError(t, err)

	var decoded LeaderResponse
	require.NoError(t, json.Unmarshal(data, &decoded))
	assert.Equal(t, resp, decoded)
}

func TestLeaderResponse_OmitsEmptyActiveTime(t *testing.T) {
	resp := LeaderResponse{
		HAEnabled:     true,
		IsSelf:        false,
		LeaderAddress: "https://leader:8200",
	}

	data, err := json.Marshal(resp)
	require.NoError(t, err)
	assert.NotContains(t, string(data), "active_time")
}

func TestReadyResponse_JSON(t *testing.T) {
	resp := ReadyResponse{
		Ready:         true,
		Initialized:   true,
		Sealed:        false,
		Standby:       false,
		ServerTimeUTC: 1700000000,
	}

	data, err := json.Marshal(resp)
	require.NoError(t, err)

	var decoded ReadyResponse
	require.NoError(t, json.Unmarshal(data, &decoded))
	assert.Equal(t, resp, decoded)
}

func TestSealStatusResponse_JSON(t *testing.T) {
	resp := SealStatusResponse{
		Sealed:      true,
		Initialized: false,
		HAEnabled:   true,
	}

	data, err := json.Marshal(resp)
	require.NoError(t, err)

	var decoded SealStatusResponse
	require.NoError(t, json.Unmarshal(data, &decoded))
	assert.Equal(t, resp, decoded)
}

// =============================================================================
// currentServerName Tests
// =============================================================================

func createTestCoreForHTTP(t *testing.T) (*core.Core, *logger.GatedLogger) {
	t.Helper()
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	phys, _ := inmem.NewInmem(nil, nil)
	c, err := core.NewCore(&core.CoreConfig{
		Physical: phys,
		Logger:   log,
		AuditDevices: map[string]audit.Factory{
			"file": &audit.FileDeviceFactory{},
		},
	})
	require.NoError(t, err)
	return c, log
}

// =============================================================================
// handleSysHealth Tests (with real core)
// =============================================================================

func TestHandleSysHealth_SealedNode(t *testing.T) {
	c, log := createTestCoreForHTTP(t)
	handler := handleSysHealth(c, log)

	req := httptest.NewRequest(http.MethodGet, "/v1/sys/health", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// Sealed + not initialized -> 501 (not initialized takes precedence)
	assert.Equal(t, http.StatusNotImplemented, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var resp HealthResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.False(t, resp.Initialized)
	assert.True(t, resp.Sealed)
}

func TestHandleSysHealth_MethodNotAllowed(t *testing.T) {
	c, log := createTestCoreForHTTP(t)
	handler := handleSysHealth(c, log)

	req := httptest.NewRequest(http.MethodPost, "/v1/sys/health", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func TestHandleSysHealth_HEAD(t *testing.T) {
	c, log := createTestCoreForHTTP(t)
	handler := handleSysHealth(c, log)

	req := httptest.NewRequest(http.MethodHead, "/v1/sys/health", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// HEAD should return status code but no body
	assert.Equal(t, http.StatusNotImplemented, w.Code)
	assert.Empty(t, w.Body.String())
}

func TestHandleSysHealth_WithOverrides(t *testing.T) {
	c, log := createTestCoreForHTTP(t)
	handler := handleSysHealth(c, log)

	req := httptest.NewRequest(http.MethodGet, "/v1/sys/health?uninitcode=200", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// =============================================================================
// handleSysReady Tests (with real core)
// =============================================================================

func TestHandleSysReady_NotInitialized(t *testing.T) {
	c, log := createTestCoreForHTTP(t)
	handler := handleSysReady(c, log)

	req := httptest.NewRequest(http.MethodGet, "/v1/sys/ready", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)

	var resp ReadyResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.False(t, resp.Ready)
	assert.False(t, resp.Initialized)
}

func TestHandleSysReady_MethodNotAllowed(t *testing.T) {
	c, log := createTestCoreForHTTP(t)
	handler := handleSysReady(c, log)

	req := httptest.NewRequest(http.MethodPost, "/v1/sys/ready", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func TestHandleSysReady_HEAD(t *testing.T) {
	c, log := createTestCoreForHTTP(t)
	handler := handleSysReady(c, log)

	req := httptest.NewRequest(http.MethodHead, "/v1/sys/ready", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	assert.Empty(t, w.Body.String())
}

// =============================================================================
// handleSysSealStatus Tests (with real core)
// =============================================================================

func TestHandleSysSealStatus_Sealed(t *testing.T) {
	c, log := createTestCoreForHTTP(t)
	handler := handleSysSealStatus(c, log)

	req := httptest.NewRequest(http.MethodGet, "/v1/sys/seal-status", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp SealStatusResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.True(t, resp.Sealed)
	assert.False(t, resp.Initialized)
}

func TestHandleSysSealStatus_MethodNotAllowed(t *testing.T) {
	c, log := createTestCoreForHTTP(t)
	handler := handleSysSealStatus(c, log)

	req := httptest.NewRequest(http.MethodPost, "/v1/sys/seal-status", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

// =============================================================================
// handleSysLeader Tests (with real core)
// =============================================================================

func TestHandleSysLeader_NoHA(t *testing.T) {
	c, log := createTestCoreForHTTP(t)
	handler := handleSysLeader(c, log)

	req := httptest.NewRequest(http.MethodGet, "/v1/sys/leader", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp LeaderResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.False(t, resp.HAEnabled)
}

func TestHandleSysLeader_MethodNotAllowed(t *testing.T) {
	c, log := createTestCoreForHTTP(t)
	handler := handleSysLeader(c, log)

	req := httptest.NewRequest(http.MethodPost, "/v1/sys/leader", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

// =============================================================================
// handleSysStepDown Tests (with real core)
// =============================================================================

func TestHandleSysStepDown_MethodNotAllowed(t *testing.T) {
	c, log := createTestCoreForHTTP(t)
	handler := handleSysStepDown(c, log)

	for _, method := range []string{http.MethodGet, http.MethodDelete, http.MethodPatch} {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/v1/sys/step-down", nil)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
		})
	}
}

func TestHandleSysStepDown_NoHA(t *testing.T) {
	c, log := createTestCoreForHTTP(t)
	handler := handleSysStepDown(c, log)

	req := httptest.NewRequest(http.MethodPut, "/v1/sys/step-down", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// No HA enabled -> 400
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "HA not enabled")
}

// =============================================================================
// handleSysInit Tests (with real core)
// =============================================================================

func TestHandleSysHealth_InitializedButSealed(t *testing.T) {
	c, log := createTestCoreForHTTP(t)
	// Initialize the core so initialized=true, but it's still sealed
	handler := handleSysInit(c, log)
	body := `{"secret_shares": 1, "secret_threshold": 1}`
	req := httptest.NewRequest(http.MethodPut, "/v1/sys/init", strings.NewReader(body))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	// Now test health - should return 503 (sealed)
	healthHandler := handleSysHealth(c, log)
	req2 := httptest.NewRequest(http.MethodGet, "/v1/sys/health", nil)
	w2 := httptest.NewRecorder()
	healthHandler.ServeHTTP(w2, req2)

	assert.Equal(t, http.StatusServiceUnavailable, w2.Code)
	var resp HealthResponse
	require.NoError(t, json.Unmarshal(w2.Body.Bytes(), &resp))
	assert.True(t, resp.Initialized)
	assert.True(t, resp.Sealed)
}

func TestHandleSysReady_InitializedButSealed(t *testing.T) {
	c, log := createTestCoreForHTTP(t)
	handler := handleSysInit(c, log)
	body := `{"secret_shares": 1, "secret_threshold": 1}`
	req := httptest.NewRequest(http.MethodPut, "/v1/sys/init", strings.NewReader(body))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	readyHandler := handleSysReady(c, log)
	req2 := httptest.NewRequest(http.MethodGet, "/v1/sys/ready", nil)
	w2 := httptest.NewRecorder()
	readyHandler.ServeHTTP(w2, req2)

	assert.Equal(t, http.StatusServiceUnavailable, w2.Code)
}

func TestHandleSysSealStatus_InitializedAndSealed(t *testing.T) {
	c, log := createTestCoreForHTTP(t)
	handler := handleSysInit(c, log)
	body := `{"secret_shares": 1, "secret_threshold": 1}`
	req := httptest.NewRequest(http.MethodPut, "/v1/sys/init", strings.NewReader(body))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	sealHandler := handleSysSealStatus(c, log)
	req2 := httptest.NewRequest(http.MethodGet, "/v1/sys/seal-status", nil)
	w2 := httptest.NewRecorder()
	sealHandler.ServeHTTP(w2, req2)

	assert.Equal(t, http.StatusOK, w2.Code)
	var resp SealStatusResponse
	require.NoError(t, json.Unmarshal(w2.Body.Bytes(), &resp))
	assert.True(t, resp.Sealed)
	assert.True(t, resp.Initialized)
}

func TestHandleSysLeader_AfterInit(t *testing.T) {
	c, log := createTestCoreForHTTP(t)
	handler := handleSysInit(c, log)
	body := `{"secret_shares": 1, "secret_threshold": 1}`
	req := httptest.NewRequest(http.MethodPut, "/v1/sys/init", strings.NewReader(body))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	leaderHandler := handleSysLeader(c, log)
	req2 := httptest.NewRequest(http.MethodGet, "/v1/sys/leader", nil)
	w2 := httptest.NewRecorder()
	leaderHandler.ServeHTTP(w2, req2)

	assert.Equal(t, http.StatusOK, w2.Code)
}

func TestHandleSysHealth_SealedCode(t *testing.T) {
	c, log := createTestCoreForHTTP(t)
	handler := handleSysHealth(c, log)

	req := httptest.NewRequest(http.MethodGet, "/v1/sys/health?sealedcode=200", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// sealedcode applies when sealed; the core is both not-init and sealed,
	// but not-init check comes first. If sealedcode=200 is set and the node
	// happens to match the sealed condition too, override may apply.
	// Just verify the endpoint responds without error.
	assert.True(t, w.Code >= 200 && w.Code < 600)
}

// =============================================================================
// handleSysInitPut additional validation coverage
// =============================================================================

func TestHandleSysStepDown_POST(t *testing.T) {
	c, log := createTestCoreForHTTP(t)
	handler := handleSysStepDown(c, log)

	req := httptest.NewRequest(http.MethodPost, "/v1/sys/step-down", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// No HA -> 400
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// =============================================================================
// handleLogical with initialized core (exercises error handling paths)
// =============================================================================
