package core

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	aeadwrapper "github.com/openbao/go-kms-wrapping/wrappers/aead/v2"
	"github.com/stephnangue/warden/audit"
	"github.com/stephnangue/warden/core/seal"
	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/physical/inmem"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testAuditDeviceForPreInit is a minimal audit device for testing
type testAuditDeviceForPreInit struct {
	name string
}

func (d *testAuditDeviceForPreInit) LogRequest(ctx context.Context, entry *audit.LogEntry) error {
	return nil
}

func (d *testAuditDeviceForPreInit) LogResponse(ctx context.Context, entry *audit.LogEntry) error {
	return nil
}

func (d *testAuditDeviceForPreInit) LogTestRequest(ctx context.Context) error {
	return nil
}

func (d *testAuditDeviceForPreInit) Close() error {
	return nil
}

func (d *testAuditDeviceForPreInit) Name() string {
	return d.name
}

func (d *testAuditDeviceForPreInit) Enabled() bool {
	return true
}

func (d *testAuditDeviceForPreInit) SetEnabled(enabled bool) {
}

func (d *testAuditDeviceForPreInit) HandleRequest(w http.ResponseWriter, r *http.Request) error {
	return nil
}

func (d *testAuditDeviceForPreInit) GetType() string {
	return "file"
}

func (d *testAuditDeviceForPreInit) GetClass() string {
	return "audit"
}

func (d *testAuditDeviceForPreInit) GetDescription() string {
	return "test audit device"
}

func (d *testAuditDeviceForPreInit) GetAccessor() string {
	return ""
}

func (d *testAuditDeviceForPreInit) Cleanup(ctx context.Context) {
}

func (d *testAuditDeviceForPreInit) Setup(ctx context.Context, conf map[string]any) error {
	return nil
}

func (d *testAuditDeviceForPreInit) Initialize(ctx context.Context) error {
	return nil
}

func (d *testAuditDeviceForPreInit) Config() map[string]any {
	return map[string]any{}
}

// testAuditFactoryForPreInit creates test audit devices
type testAuditFactoryForPreInit struct{}

func (f *testAuditFactoryForPreInit) Type() string {
	return "file"
}

func (f *testAuditFactoryForPreInit) Class() string {
	return "audit"
}

func (f *testAuditFactoryForPreInit) Create(ctx context.Context, mountPath, description, accessor string, config map[string]any) (audit.Device, error) {
	return &testAuditDeviceForPreInit{name: mountPath}, nil
}

func (f *testAuditFactoryForPreInit) Initialize(logger *logger.GatedLogger) error {
	return nil
}

// testAuditDevicesForPreInit returns a map of test audit device factories
func testAuditDevicesForPreInit() map[string]audit.Factory {
	return map[string]audit.Factory{
		"file": &testAuditFactoryForPreInit{},
	}
}

// createTestCoreForPreInit creates a core for pre-init handler testing
func createTestCoreForPreInit(t *testing.T) (*Core, *logger.GatedLogger) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})

	// Create physical backend
	phys, err := inmem.NewInmem(nil, log)
	require.NoError(t, err)

	// Create test seal with Shamir wrapper
	shamirWrapper := aeadwrapper.NewShamirWrapper()
	testSeal := NewDefaultSeal(seal.NewAccess(shamirWrapper))

	coreConfig := &CoreConfig{
		Physical:     phys,
		Seal:         testSeal,
		Logger:       log,
		AuditDevices: testAuditDevicesForPreInit(),
		// TokenStore is now created internally in CreateCore
	}

	// Use NewCore which sets up barrier and other components
	core, err := NewCore(coreConfig)
	require.NoError(t, err)

	return core, log
}

func TestPreInitHandler_TryHandle_InitRequest(t *testing.T) {
	// Setup
	core, log := createTestCoreForPreInit(t)
	defer core.Shutdown()

	handler := NewPreInitHandler(core, log)

	// Create init request
	reqBody := map[string]interface{}{
		"secret_shares":    5,
		"secret_threshold": 3,
	}
	body, err := json.Marshal(reqBody)
	require.NoError(t, err)

	req := httptest.NewRequest("POST", "/v1/sys/init", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	// Execute
	handled, err := handler.TryHandle(w, req)

	// Assert
	assert.NoError(t, err)
	assert.True(t, handled, "Pre-init handler should handle /sys/init POST")
	assert.Equal(t, http.StatusOK, w.Code)

	// Verify response contains root token and keys
	var resp map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.NotEmpty(t, resp["root_token"], "Response should contain root_token")
	assert.NotEmpty(t, resp["keys"], "Response should contain keys")
}

func TestPreInitHandler_TryHandle_InitRequest_WithoutV1Prefix(t *testing.T) {
	// Setup
	core, log := createTestCoreForPreInit(t)
	defer core.Shutdown()

	handler := NewPreInitHandler(core, log)

	// Create init request without /v1 prefix
	reqBody := map[string]interface{}{
		"secret_shares":    5,
		"secret_threshold": 3,
	}
	body, err := json.Marshal(reqBody)
	require.NoError(t, err)

	req := httptest.NewRequest("POST", "/sys/init", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	// Execute
	handled, err := handler.TryHandle(w, req)

	// Assert
	assert.NoError(t, err)
	assert.True(t, handled, "Pre-init handler should handle /sys/init POST without /v1 prefix")
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestPreInitHandler_TryHandle_PassThrough_NonInitPaths(t *testing.T) {
	tests := []struct {
		name   string
		method string
		path   string
	}{
		{"health endpoint", "GET", "/v1/sys/health"},
		{"seal-status endpoint", "GET", "/v1/sys/seal-status"},
		{"providers list", "GET", "/v1/sys/providers"},
		{"auth list", "GET", "/v1/sys/auth"},
		{"non-sys path", "GET", "/v1/aws/s3/buckets"},
		{"root path", "GET", "/"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			core, log := createTestCoreForPreInit(t)
			defer core.Shutdown()

			handler := NewPreInitHandler(core, log)

			req := httptest.NewRequest(tt.method, tt.path, nil)
			w := httptest.NewRecorder()

			// Execute
			handled, err := handler.TryHandle(w, req)

			// Assert
			assert.NoError(t, err)
			assert.False(t, handled, "Pre-init handler should NOT handle %s %s", tt.method, tt.path)
		})
	}
}

func TestPreInitHandler_TryHandle_PassThrough_WrongMethod(t *testing.T) {
	// Setup
	core, log := createTestCoreForPreInit(t)
	defer core.Shutdown()

	handler := NewPreInitHandler(core, log)

	// GET request to /sys/init (should be POST)
	req := httptest.NewRequest("GET", "/v1/sys/init", nil)
	w := httptest.NewRecorder()

	// Execute
	handled, err := handler.TryHandle(w, req)

	// Assert
	assert.NoError(t, err)
	assert.False(t, handled, "Pre-init handler should NOT handle GET /sys/init (requires POST)")
}

func TestPreInitHandler_HandleInit_AlreadyInitialized(t *testing.T) {
	// Setup
	core, log := createTestCoreForPreInit(t)
	defer core.Shutdown()

	handler := NewPreInitHandler(core, log)

	// Initialize once
	reqBody := map[string]interface{}{
		"secret_shares":    5,
		"secret_threshold": 3,
	}
	body, err := json.Marshal(reqBody)
	require.NoError(t, err)

	req1 := httptest.NewRequest("POST", "/v1/sys/init", bytes.NewReader(body))
	req1.Header.Set("Content-Type", "application/json")
	w1 := httptest.NewRecorder()

	handled, err := handler.TryHandle(w1, req1)
	require.NoError(t, err)
	require.True(t, handled)
	require.Equal(t, http.StatusOK, w1.Code)

	// Try to initialize again
	body2, _ := json.Marshal(reqBody)
	req2 := httptest.NewRequest("POST", "/v1/sys/init", bytes.NewReader(body2))
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()

	handled2, err := handler.TryHandle(w2, req2)

	// Assert
	assert.NoError(t, err)
	assert.True(t, handled2, "Pre-init handler should still handle the request")
	assert.Equal(t, http.StatusBadRequest, w2.Code, "Should return 400 for already initialized")
	assert.Contains(t, w2.Body.String(), "already initialized", "Error message should indicate already initialized")
}

func TestPreInitHandler_HandleInit_InvalidJSON(t *testing.T) {
	// Setup
	core, log := createTestCoreForPreInit(t)
	defer core.Shutdown()

	handler := NewPreInitHandler(core, log)

	// Send malformed JSON
	req := httptest.NewRequest("POST", "/v1/sys/init", bytes.NewReader([]byte("{invalid json}")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	// Execute
	handled, err := handler.TryHandle(w, req)

	// Assert
	assert.NoError(t, err)
	assert.True(t, handled, "Pre-init handler should handle the request")
	assert.Equal(t, http.StatusBadRequest, w.Code, "Should return 400 for invalid JSON")
}

func TestPreInitHandler_HandleInit_InvalidParameters(t *testing.T) {
	tests := []struct {
		name            string
		secretShares    int
		secretThreshold int
		expectedCode    int
		expectedError   string
	}{
		{
			name:            "threshold greater than shares",
			secretShares:    3,
			secretThreshold: 5,
			expectedCode:    http.StatusBadRequest,
			expectedError:   "threshold cannot be greater than",
		},
		{
			name:            "zero shares",
			secretShares:    0,
			secretThreshold: 0,
			expectedCode:    http.StatusOK, // Should use defaults (5, 3)
			expectedError:   "",
		},
		{
			name:            "threshold less than 1",
			secretShares:    5,
			secretThreshold: 0,
			expectedCode:    http.StatusOK, // Should use default threshold (3)
			expectedError:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			core, log := createTestCoreForPreInit(t)
			defer core.Shutdown()

			handler := NewPreInitHandler(core, log)

			reqBody := map[string]interface{}{
				"secret_shares":    tt.secretShares,
				"secret_threshold": tt.secretThreshold,
			}
			body, err := json.Marshal(reqBody)
			require.NoError(t, err)

			req := httptest.NewRequest("POST", "/v1/sys/init", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			// Execute
			handled, err := handler.TryHandle(w, req)

			// Assert
			assert.NoError(t, err)
			assert.True(t, handled)
			assert.Equal(t, tt.expectedCode, w.Code)

			if tt.expectedError != "" {
				assert.Contains(t, w.Body.String(), tt.expectedError)
			}
		})
	}
}

func TestPreInitHandler_HandleInit_CustomShares(t *testing.T) {
	// Setup
	core, log := createTestCoreForPreInit(t)
	defer core.Shutdown()

	handler := NewPreInitHandler(core, log)

	// Test Init with custom parameters (7 shares, 4 threshold)
	reqBody := map[string]interface{}{
		"secret_shares":    7,
		"secret_threshold": 4,
	}
	body, err := json.Marshal(reqBody)
	require.NoError(t, err)

	req := httptest.NewRequest("POST", "/v1/sys/init", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	// Execute
	handled, err := handler.TryHandle(w, req)

	// Assert
	assert.NoError(t, err)
	assert.True(t, handled)
	assert.Equal(t, http.StatusOK, w.Code)

	// Verify we got the right number of unseal keys
	var resp map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)

	keys, ok := resp["keys"].([]interface{})
	require.True(t, ok, "keys should be an array")
	assert.Len(t, keys, 7, "Should have 7 unseal keys")
}

func TestPreInitHandler_Integration_WithCore(t *testing.T) {
	// Setup: Create core with pre-init handler
	core, _ := createTestCoreForPreInit(t)
	defer core.Shutdown()

	// Verify pre-init handler is initialized
	require.NotNil(t, core.preInitHandler, "Core should have pre-init handler")

	// Send init request through Core.ServeHTTP (full integration)
	reqBody := map[string]interface{}{
		"secret_shares":    5,
		"secret_threshold": 3,
	}
	body, err := json.Marshal(reqBody)
	require.NoError(t, err)

	req := httptest.NewRequest("POST", "/v1/sys/init", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	// Execute through Core.ServeHTTP
	core.ServeHTTP(w, req)

	// Assert
	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.NotEmpty(t, resp["root_token"])
	assert.NotEmpty(t, resp["keys"])

	// Verify core is now initialized
	initialized, err := core.Initialized(context.Background())
	require.NoError(t, err)
	assert.True(t, initialized, "Core should be initialized after init request")
}
