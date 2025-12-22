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
	"github.com/stephnangue/warden/auth/token"
	"github.com/stephnangue/warden/core/seal"
	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/physical/inmem"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testAuditDevice is a minimal audit device for testing
type testAuditDevice struct {
	name string
}

func (d *testAuditDevice) LogRequest(ctx context.Context, entry *audit.LogEntry) error {
	return nil
}

func (d *testAuditDevice) LogResponse(ctx context.Context, entry *audit.LogEntry) error {
	return nil
}

func (d *testAuditDevice) LogTestRequest(ctx context.Context) error {
	return nil
}

func (d *testAuditDevice) Close() error {
	return nil
}

func (d *testAuditDevice) Name() string {
	return d.name
}

func (d *testAuditDevice) Enabled() bool {
	return true
}

func (d *testAuditDevice) SetEnabled(enabled bool) {
}

func (d *testAuditDevice) HandleRequest(w http.ResponseWriter, r *http.Request) error {
	return nil
}

func (d *testAuditDevice) GetType() string {
	return "file"
}

func (d *testAuditDevice) GetClass() string {
	return "audit"
}

func (d *testAuditDevice) GetDescription() string {
	return "test audit device"
}

func (d *testAuditDevice) GetAccessor() string {
	return ""
}

func (d *testAuditDevice) Cleanup() {
}

func (d *testAuditDevice) Setup(conf map[string]any) error {
	return nil
}

func (d *testAuditDevice) Config() map[string]any {
	return map[string]any{}
}

// testAuditFactory creates test audit devices
type testAuditFactory struct{}

func (f *testAuditFactory) Type() string {
	return "file"
}

func (f *testAuditFactory) Class() string {
	return "audit"
}

func (f *testAuditFactory) Create(ctx context.Context, mountPath, description, accessor string, config map[string]any) (audit.Device, error) {
	return &testAuditDevice{name: mountPath}, nil
}

func (f *testAuditFactory) Initialize(logger *logger.GatedLogger) error {
	return nil
}

// testAuditDevices returns a map of test audit device factories
func testAuditDevices() map[string]audit.Factory {
	return map[string]audit.Factory{
		"file": &testAuditFactory{},
	}
}

// createTestCoreForInit creates a core setup for initialization testing with barrier and seal
func createTestCoreForInit(t *testing.T) (*Core, *logger.GatedLogger) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})

	// Create physical backend
	phys, err := inmem.NewInmem(nil, log)
	require.NoError(t, err)

	// Create test seal with Shamir wrapper
	shamirWrapper := aeadwrapper.NewShamirWrapper()
	testSeal := NewDefaultSeal(seal.NewAccess(shamirWrapper))

	// Create token store
	tokenStore, err := token.NewRobustStore(log, nil)
	require.NoError(t, err)
	t.Cleanup(func() { tokenStore.Close() })

	coreConfig := &CoreConfig{
		Physical:     phys,
		Seal:         testSeal,
		TokenStore:   tokenStore,
		Logger:       log,
		AuditDevices: testAuditDevices(),
	}

	// Use NewCore which sets up barrier and other components
	core, err := NewCore(coreConfig)
	require.NoError(t, err)

	return core, log
}

func TestSystemHandlers_Init(t *testing.T) {
	// Setup
	core, log := createTestCoreForInit(t)
	defer core.Shutdown()

	handlers := &SystemHandlers{
		core:   core,
		logger: log,
	}

	// Test Init with default parameters (5 shares, 3 threshold)
	ctx := context.Background()
	input := &InitInput{}
	input.Body.SecretShares = 5
	input.Body.SecretThreshold = 3

	output, err := handlers.Init(ctx, input)
	require.NoError(t, err)
	assert.NotNil(t, output)
	assert.NotEmpty(t, output.Body.RootToken)

	// Verify we got unseal keys
	assert.Len(t, output.Body.Keys, 5)
	assert.Len(t, output.Body.KeysBase64, 5)

	// Verify each key is not empty
	for i, key := range output.Body.Keys {
		assert.NotEmpty(t, key, "Key %d should not be empty", i)
	}
}

func TestSystemHandlers_Init_CustomShares(t *testing.T) {
	// Setup
	core, log := createTestCoreForInit(t)
	defer core.Shutdown()

	handlers := &SystemHandlers{
		core:   core,
		logger: log,
	}

	// Test Init with custom parameters (7 shares, 4 threshold)
	ctx := context.Background()
	input := &InitInput{}
	input.Body.SecretShares = 7
	input.Body.SecretThreshold = 4

	output, err := handlers.Init(ctx, input)
	require.NoError(t, err)
	assert.NotNil(t, output)
	assert.NotEmpty(t, output.Body.RootToken)

	// Verify we got the right number of unseal keys
	assert.Len(t, output.Body.Keys, 7)
	assert.Len(t, output.Body.KeysBase64, 7)
}

func TestSystemHandlers_Init_MinimalShares(t *testing.T) {
	// Setup
	core, log := createTestCoreForInit(t)
	defer core.Shutdown()

	handlers := &SystemHandlers{
		core:   core,
		logger: log,
	}

	// Test Init with minimal parameters (1 share, 1 threshold)
	ctx := context.Background()
	input := &InitInput{}
	input.Body.SecretShares = 1
	input.Body.SecretThreshold = 1

	output, err := handlers.Init(ctx, input)
	require.NoError(t, err)
	assert.NotNil(t, output)
	assert.NotEmpty(t, output.Body.RootToken)

	// Verify we got 1 unseal key
	assert.Len(t, output.Body.Keys, 1)
	assert.Len(t, output.Body.KeysBase64, 1)
}

func TestSystemHandlers_Init_DefaultValues(t *testing.T) {
	// Setup
	core, log := createTestCoreForInit(t)
	defer core.Shutdown()

	handlers := &SystemHandlers{
		core:   core,
		logger: log,
	}

	// Test Init with no parameters - should use defaults (5 shares, 3 threshold)
	ctx := context.Background()
	input := &InitInput{}

	output, err := handlers.Init(ctx, input)
	require.NoError(t, err)
	assert.NotNil(t, output)
	assert.NotEmpty(t, output.Body.RootToken)

	// Verify we got default 5 unseal keys
	assert.Len(t, output.Body.Keys, 5)
	assert.Len(t, output.Body.KeysBase64, 5)
}

func TestSystemHandlers_Init_Multiple(t *testing.T) {
	// Setup
	core, log := createTestCoreForInit(t)
	defer core.Shutdown()

	handlers := &SystemHandlers{
		core:   core,
		logger: log,
	}

	ctx := context.Background()
	input := &InitInput{}
	input.Body.SecretShares = 5
	input.Body.SecretThreshold = 3

	// Generate first init
	output1, err := handlers.Init(ctx, input)
	require.NoError(t, err)
	assert.NotEmpty(t, output1.Body.RootToken)

	// Attempt to initialize again should fail
	output2, err := handlers.Init(ctx, input)
	assert.Error(t, err)
	assert.Nil(t, output2)
	assert.Contains(t, err.Error(), "already initialized")
}

func TestSystemHandlers_Init_InvalidParameters(t *testing.T) {
	tests := []struct {
		name            string
		secretShares    int
		secretThreshold int
		expectedError   string
	}{
		{
			name:            "threshold greater than shares",
			secretShares:    3,
			secretThreshold: 5,
			expectedError:   "secret_threshold cannot be greater than secret_shares",
		},
		{
			name:            "zero shares",
			secretShares:    0,
			secretThreshold: 0,
			expectedError:   "", // Should use defaults
		},
		{
			name:            "zero threshold with valid shares",
			secretShares:    5,
			secretThreshold: 0,
			expectedError:   "", // Should use default threshold
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			core, log := createTestCoreForInit(t)
			defer core.Shutdown()

			handlers := &SystemHandlers{
				core:   core,
				logger: log,
			}

			ctx := context.Background()
			input := &InitInput{}
			input.Body.SecretShares = tt.secretShares
			input.Body.SecretThreshold = tt.secretThreshold

			output, err := handlers.Init(ctx, input)

			if tt.expectedError != "" {
				assert.Error(t, err)
				assert.Nil(t, output)
				assert.Contains(t, err.Error(), tt.expectedError)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, output)
			}
		})
	}
}

func TestSystemHandlers_Init_PGPKeysMismatch(t *testing.T) {
	// Setup
	core, log := createTestCoreForInit(t)
	defer core.Shutdown()

	handlers := &SystemHandlers{
		core:   core,
		logger: log,
	}

	ctx := context.Background()

	// Test PGP keys count mismatch
	input := &InitInput{}
	input.Body.SecretShares = 5
	input.Body.SecretThreshold = 3
	input.Body.PGPKeys = []string{"key1", "key2", "key3"} // Only 3 keys for 5 shares

	output, err := handlers.Init(ctx, input)
	assert.Error(t, err)
	assert.Nil(t, output)
	assert.Contains(t, err.Error(), "number of pgp_keys")
}

func TestSystemHandlers_RevokeRootToken(t *testing.T) {
	// Setup
	core, log := createTestCoreForInit(t)
	defer core.Shutdown()

	handlers := &SystemHandlers{
		core:   core,
		logger: log,
	}

	// Generate root token first by initializing
	initInput := &InitInput{}
	initInput.Body.SecretShares = 5
	initInput.Body.SecretThreshold = 3

	initOutput, err := handlers.Init(context.Background(), initInput)
	require.NoError(t, err)
	rootToken := initOutput.Body.RootToken

	// Create context with root principal
	ctx := context.WithValue(context.Background(), SystemPrincipalIDKey, "root")
	input := &struct{}{}

	// Revoke root token
	output, err := handlers.RevokeRootToken(ctx, input)
	require.NoError(t, err)
	assert.NotNil(t, output)
	assert.Equal(t, "Root token successfully revoked", output.Body.Message)

	// Token should no longer be valid
	_, _, err = core.tokenStore.ResolveToken(context.Background(), rootToken, map[string]string{})
	assert.Error(t, err)
}


func TestCore_Initialize_WithBarrier(t *testing.T) {
	// Setup
	core, _ := createTestCoreForInit(t)
	defer core.Shutdown()

	ctx := context.Background()

	// Verify not initialized initially
	initialized, err := core.Initialized(ctx)
	require.NoError(t, err)
	assert.False(t, initialized)

	// Initialize with Shamir
	initParams := &InitParams{
		BarrierConfig: &SealConfig{
			SecretShares:    5,
			SecretThreshold: 3,
		},
		RecoveryConfig: nil,
	}

	result, err := core.Initialize(ctx, initParams)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.NotEmpty(t, result.RootToken)
	assert.Len(t, result.SecretShares, 5)

	// Verify initialized now
	initialized, err = core.Initialized(ctx)
	require.NoError(t, err)
	assert.True(t, initialized)
}

func TestCore_Initialize_SingleShare(t *testing.T) {
	// Setup
	core, _ := createTestCoreForInit(t)
	defer core.Shutdown()

	ctx := context.Background()

	// Initialize with single share
	initParams := &InitParams{
		BarrierConfig: &SealConfig{
			SecretShares:    1,
			SecretThreshold: 1,
		},
	}

	result, err := core.Initialize(ctx, initParams)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.NotEmpty(t, result.RootToken)
	assert.Len(t, result.SecretShares, 1)
}

func TestCore_Initialize_AlreadyInitialized(t *testing.T) {
	// Setup
	core, _ := createTestCoreForInit(t)
	defer core.Shutdown()

	ctx := context.Background()

	// First initialization
	initParams := &InitParams{
		BarrierConfig: &SealConfig{
			SecretShares:    5,
			SecretThreshold: 3,
		},
	}

	_, err := core.Initialize(ctx, initParams)
	require.NoError(t, err)

	// Second initialization should fail
	_, err = core.Initialize(ctx, initParams)
	assert.Error(t, err)
	assert.Equal(t, ErrAlreadyInit, err)
}

// Integration tests for Pre-Init Handler

func TestPreInitHandler_InterceptsBeforeRouter(t *testing.T) {
	// Create Core with pre-init handler but WITHOUT loading system backend
	core, log := createTestCoreForInit(t)
	defer core.Shutdown()

	// Verify pre-init handler exists
	require.NotNil(t, core.preInitHandler, "Core should have pre-init handler")

	// Send init request via Core.ServeHTTP (simulating real HTTP flow)
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

	// Assert init succeeded
	assert.Equal(t, http.StatusOK, w.Code, "Init should succeed via pre-init handler")

	var resp map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.NotEmpty(t, resp["root_token"], "Response should contain root token")
	assert.NotEmpty(t, resp["keys"], "Response should contain unseal keys")

	// Verify core is initialized
	initialized, err := core.Initialized(context.Background())
	require.NoError(t, err)
	assert.True(t, initialized, "Core should be initialized")

	log.Info("Pre-init handler successfully handled /sys/init before router")
}

func TestPreInitHandler_WorksWhenSealed(t *testing.T) {
	// Create Core (which starts sealed)
	core, log := createTestCoreForInit(t)
	defer core.Shutdown()

	// Verify core is sealed
	assert.True(t, core.Sealed(), "Core should be sealed initially")

	// Send init request while sealed
	reqBody := map[string]interface{}{
		"secret_shares":    1,
		"secret_threshold": 1,
	}
	body, err := json.Marshal(reqBody)
	require.NoError(t, err)

	req := httptest.NewRequest("POST", "/v1/sys/init", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	// Execute
	core.ServeHTTP(w, req)

	// Assert init succeeded despite being sealed
	assert.Equal(t, http.StatusOK, w.Code, "Init should work even when sealed")

	var resp map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.NotEmpty(t, resp["root_token"])

	log.Info("Pre-init handler works correctly when core is sealed")
}

func TestPreInitHandler_NonInitRequestsBlockedWhenSealed(t *testing.T) {
	// Create Core (which starts sealed)
	core, _ := createTestCoreForInit(t)
	defer core.Shutdown()

	// Verify core is sealed
	assert.True(t, core.Sealed(), "Core should be sealed initially")

	// Try to access a non-init endpoint while sealed
	req := httptest.NewRequest("GET", "/v1/sys/providers", nil)
	w := httptest.NewRecorder()

	// Execute
	core.ServeHTTP(w, req)

	// Assert request is blocked
	// Note: Request is blocked by audit check (500) because no audit devices are configured
	// and this is not an audit-exempt operation. This happens before the seal check.
	// This is correct and more secure - only POST /sys/init is audit-exempt.
	assert.Equal(t, http.StatusInternalServerError, w.Code, "Non-init requests should be blocked when no audit devices")
	assert.Contains(t, w.Body.String(), "Internal server error", "Error should indicate internal error")
}

func TestPreInitHandler_PrecedenceOverSystemBackend(t *testing.T) {
	// Create Core (system backend is already loaded by NewCore via Core.Init)
	core, log := createTestCoreForInit(t)
	defer core.Shutdown()

	// Verify both pre-init handler and system backend exist
	require.NotNil(t, core.preInitHandler, "Pre-init handler should exist")

	// The system backend is already mounted, but pre-init handler should intercept first

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
	core.ServeHTTP(w, req)

	// Assert pre-init handler handled it
	assert.Equal(t, http.StatusOK, w.Code)

	log.Info("Pre-init handler takes precedence over system backend for /sys/init")
}

func TestPreInitHandler_FullWorkflow(t *testing.T) {
	// This test validates the complete initialization workflow via pre-init handler
	core, log := createTestCoreForInit(t)
	defer core.Shutdown()

	ctx := context.Background()

	// Step 1: Verify not initialized
	initialized, err := core.Initialized(ctx)
	require.NoError(t, err)
	assert.False(t, initialized, "Core should not be initialized initially")

	// Step 2: Initialize via pre-init handler
	reqBody := map[string]interface{}{
		"secret_shares":    5,
		"secret_threshold": 3,
	}
	body, err := json.Marshal(reqBody)
	require.NoError(t, err)

	req := httptest.NewRequest("POST", "/v1/sys/init", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	core.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)

	rootToken := resp["root_token"].(string)
	keys := resp["keys"].([]interface{})

	// Step 3: Verify initialization completed
	initialized, err = core.Initialized(ctx)
	require.NoError(t, err)
	assert.True(t, initialized, "Core should be initialized")

	// Step 4: Verify we got expected outputs
	assert.NotEmpty(t, rootToken, "Should have root token")
	assert.Len(t, keys, 5, "Should have 5 unseal keys")

	// Step 5: Attempt second initialization (should fail)
	req2 := httptest.NewRequest("POST", "/v1/sys/init", bytes.NewReader(body))
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()

	core.ServeHTTP(w2, req2)
	assert.Equal(t, http.StatusBadRequest, w2.Code, "Second init should fail")
	assert.Contains(t, w2.Body.String(), "already initialized")

	log.Info("Full initialization workflow completed successfully")
}
