package core

import (
	"context"
	"crypto/rand"
	"fmt"
	"maps"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/openbao/openbao/helper/locking"
	"github.com/openbao/openbao/helper/namespace"
	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stephnangue/warden/audit"
	"github.com/stephnangue/warden/auth"
	"github.com/stephnangue/warden/authorize"
	"github.com/stephnangue/warden/cred"
	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
	"github.com/stephnangue/warden/physical/inmem"
	"github.com/stephnangue/warden/provider"
)

// mockAuditDevice implements audit.Device for testing
type mockAuditDevice struct {
	name             string
	deviceType       string
	deviceClass      string
	description      string
	accessor         string
	enabled          bool
	logRequestErr    error
	logResponseErr   error
	logRequestCalls  int
	logResponseCalls int
	lastEntry        *audit.LogEntry
	mu               sync.Mutex
}

func newMockAuditDevice(name string) *mockAuditDevice {
	return &mockAuditDevice{
		name:        name,
		deviceType:  "mock",
		deviceClass: "audit",
		enabled:     true,
	}
}

func (d *mockAuditDevice) LogRequest(ctx context.Context, entry *audit.LogEntry) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.logRequestCalls++
	d.lastEntry = entry
	return d.logRequestErr
}

func (d *mockAuditDevice) LogResponse(ctx context.Context, entry *audit.LogEntry) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.logResponseCalls++
	d.lastEntry = entry
	return d.logResponseErr
}

func (d *mockAuditDevice) LogTestRequest(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.logRequestCalls++
	return d.logRequestErr
}

func (d *mockAuditDevice) Close() error {
	return nil
}

func (d *mockAuditDevice) Name() string {
	return d.name
}

func (d *mockAuditDevice) Enabled() bool {
	return d.enabled
}

func (d *mockAuditDevice) SetEnabled(enabled bool) {
	d.enabled = enabled
}

// logical.Backend interface methods
func (d *mockAuditDevice) HandleRequest(w http.ResponseWriter, r *http.Request) error {
	return nil
}

func (d *mockAuditDevice) GetType() string {
	return d.deviceType
}

func (d *mockAuditDevice) GetClass() string {
	return d.deviceClass
}

func (d *mockAuditDevice) GetDescription() string {
	return d.description
}

func (d *mockAuditDevice) GetAccessor() string {
	return d.accessor
}

func (d *mockAuditDevice) Cleanup(ctx context.Context) {
}

func (m *mockAuditDevice) Setup(ctx context.Context, conf map[string]any) error {
	return nil
}

func (m *mockAuditDevice) Initialize(ctx context.Context) error {
	return nil
}

func (m *mockAuditDevice) Config() map[string]any {
	return map[string]any{}
}

// mockAuditFactory implements audit.Factory for testing
type mockAuditFactory struct {
	createFunc func(ctx context.Context, mountPath, description, accessor string, config map[string]any) (audit.Device, error)
	device     audit.Device
	createErr  error
}

func (f *mockAuditFactory) Type() string {
	return "mock"
}

func (f *mockAuditFactory) Class() string {
	return "audit"
}

func (f *mockAuditFactory) Create(ctx context.Context, mountPath, description, accessor string, config map[string]any) (audit.Device, error) {
	if f.createFunc != nil {
		return f.createFunc(ctx, mountPath, description, accessor, config)
	}
	if f.createErr != nil {
		return nil, f.createErr
	}
	if f.device != nil {
		return f.device, nil
	}
	return newMockAuditDevice(mountPath), nil
}

func (f *mockAuditFactory) Initialize(logger *logger.GatedLogger) error {
	return nil
}

// mockAuditManagerFull implements audit.AuditManager for testing with full functionality
type mockAuditManagerFull struct {
	devices           map[string]audit.Device
	logRequestErr     error
	logResponseErr    error
	logRequestResult  bool
	logResponseResult bool
	mu                sync.RWMutex
}

func newMockAuditManagerFull() *mockAuditManagerFull {
	return &mockAuditManagerFull{
		devices:           make(map[string]audit.Device),
		logRequestResult:  true,
		logResponseResult: true,
	}
}

func (m *mockAuditManagerFull) Reset(ctx context.Context) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	m.devices = nil

	return nil
}

func (m *mockAuditManagerFull) RegisterDevice(name string, device audit.Device) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.devices[name]; exists {
		return fmt.Errorf("device %q already registered", name)
	}
	m.devices[name] = device
	return nil
}

func (m *mockAuditManagerFull) UnregisterDevice(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.devices[name]; !exists {
		return fmt.Errorf("device %q not found", name)
	}
	delete(m.devices, name)
	return nil
}

func (m *mockAuditManagerFull) GetDevice(name string) (audit.Device, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	device, exists := m.devices[name]
	if !exists {
		return nil, fmt.Errorf("device %q not found", name)
	}
	return device, nil
}

func (m *mockAuditManagerFull) ListDevices() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	names := make([]string, 0, len(m.devices))
	for name := range m.devices {
		names = append(names, name)
	}
	return names
}

func (m *mockAuditManagerFull) LogRequest(ctx context.Context, entry *audit.LogEntry) (bool, error) {
	return m.logRequestResult, m.logRequestErr
}

func (m *mockAuditManagerFull) LogResponse(ctx context.Context, entry *audit.LogEntry) (bool, error) {
	return m.logResponseResult, m.logResponseErr
}

func (m *mockAuditManagerFull) Close() error {
	return nil
}

// mockAuditManager is a simple mock that implements the minimum audit.Manager interface
type mockAuditManager struct{}

func (m *mockAuditManager) RegisterDevice(name string, device audit.Device) error {
	return nil
}

func (m *mockAuditManager) UnregisterDevice(name string) error {
	return nil
}

func (m *mockAuditManager) GetDevice(name string) (audit.Device, error) {
	return nil, nil
}

func (m *mockAuditManager) ListDevices() []string {
	return nil
}

func (m *mockAuditManager) LogRequest(ctx context.Context, entry *audit.LogEntry) (bool, error) {
	return true, nil
}

func (m *mockAuditManager) LogResponse(ctx context.Context, entry *audit.LogEntry) (bool, error) {
	return true, nil
}

func (m *mockAuditManager) Close() error {
	return nil
}

func (m *mockAuditManager) Reset(ctx context.Context) error {
	return nil
}

// mockTokenStore implements the auth.TokenStore interface for testing
type mockTokenStore struct{}

func (m *mockTokenStore) GenerateToken(ctx context.Context, tokenType string, authData *logical.AuthData) (*logical.TokenEntry, error) {
	return nil, nil
}

func (m *mockTokenStore) ResolveToken(ctx context.Context, tokenValue string) (string, string, error) {
	return "", "", nil
}

func (m *mockTokenStore) GetToken(tokenValue string) *logical.TokenEntry {
	return nil
}

func (m *mockTokenStore) GetMetrics() map[string]int64 {
	return nil
}

func (m *mockTokenStore) Close() {}

func (m *mockTokenStore) GenerateRootToken() (string, error) {
	return "", nil
}

func (m *mockTokenStore) RevokeRootToken() error {
	return nil
}

// mockAuthFactory implements auth.Factory for testing
type mockAuthFactory struct{}

func (f *mockAuthFactory) Type() string {
	return "mock"
}

func (f *mockAuthFactory) Class() string {
	return "auth"
}

func (f *mockAuthFactory) Create(ctx context.Context,
	mountPath string,
	description string,
	accessor string,
	config map[string]any,
	log *logger.GatedLogger,
	tokenStore auth.TokenStore,
	roles *authorize.RoleRegistry,
	accessControl *authorize.AccessControl,
	auditAccess audit.AuditAccess,
	storageView sdklogical.Storage) (logical.Backend, error) {
	backend := newMockAuthMethod()
	if err := backend.Setup(ctx, config); err != nil {
		return nil, err
	}
	backend.setupRouter()
	return backend, nil
}

func (f *mockAuthFactory) Initialize(logger *logger.GatedLogger) error {
	return nil
}

func (f *mockAuthFactory) ValidateConfig(config map[string]any) error {
	return nil
}

// mockAuthMethod implements logical.Backend for testing (used as auth method)
type mockAuthMethod struct {
	config map[string]any
	mu     sync.RWMutex
	router *chi.Mux
}

func (m *mockAuthMethod) HandleRequest(w http.ResponseWriter, r *http.Request) error {
	m.router.ServeHTTP(w, r)

	return nil
}

func (p *mockAuthMethod) setupRouter() {
	r := chi.NewRouter()

	r.Route("/", func(traffic chi.Router) {
		traffic.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		traffic.HandleFunc("/profile", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
	})

	p.router = r
}

func (m *mockAuthMethod) GetType() string {
	return "mock"
}

func (m *mockAuthMethod) GetClass() string {
	return "auth"
}

func (m *mockAuthMethod) GetDescription() string {
	return "Mock auth method"
}

func (m *mockAuthMethod) GetAccessor() string {
	return "mock_accessor"
}

func (m *mockAuthMethod) Cleanup(ctx context.Context) {}

func (m *mockAuthMethod) Setup(ctx context.Context, conf map[string]any) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.config = make(map[string]any)
	maps.Copy(m.config, conf)
	return nil
}

func (m *mockAuthMethod) Initialize(ctx context.Context) error {
	return nil
}

func (m *mockAuthMethod) Config() map[string]any {
	m.mu.RLock()
	defer m.mu.RUnlock()
	config := make(map[string]any)
	maps.Copy(config, m.config)
	return config
}

func newMockAuthMethod() *mockAuthMethod {
	return &mockAuthMethod{}
}

// mockProviderFactory implements provider.Factory for testing
type mockProviderFactory struct{}

func (f *mockProviderFactory) Type() string {
	return "mock"
}

func (f *mockProviderFactory) Class() string {
	return "provider"
}

func (f *mockProviderFactory) Create(ctx context.Context,
	mountPath string,
	description string,
	accessor string,
	config map[string]any,
	log *logger.GatedLogger,
	tokenAccess logical.TokenAccess,
	roles *authorize.RoleRegistry,
	credSources *cred.CredSourceRegistry,
	auditAccess audit.AuditAccess,
	storageView sdklogical.Storage) (logical.Backend, error) {
	backend := newMockProvider()
	if err := backend.Setup(ctx, config); err != nil {
		return nil, err
	}
	backend.setupRouter()
	return backend, nil
}

func (f *mockProviderFactory) Initialize(logger *logger.GatedLogger) error {
	return nil
}

func (f *mockProviderFactory) ValidateConfig(config map[string]any) error {
	return nil
}

// mockProvider implements logical.Backend for testing (used as provider)
type mockProvider struct {
	config map[string]any
	mu     sync.RWMutex
	router *chi.Mux
}

func (m *mockProvider) HandleRequest(w http.ResponseWriter, r *http.Request) error {
	m.router.ServeHTTP(w, r)

	return nil
}

func (p *mockProvider) setupRouter() {
	r := chi.NewRouter()

	r.Route("/", func(traffic chi.Router) {
		traffic.HandleFunc("/gateway*", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		traffic.HandleFunc("/profile", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
	})

	p.router = r
}

func (m *mockProvider) GetType() string {
	return "mock"
}

func (m *mockProvider) GetClass() string {
	return "provider"
}

func (m *mockProvider) GetDescription() string {
	return "Mock provider"
}

func (m *mockProvider) GetAccessor() string {
	return "mock_accessor"
}

func (m *mockProvider) Cleanup(ctx context.Context) {}

func (m *mockProvider) Setup(ctx context.Context, conf map[string]any) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.config = make(map[string]any)
	maps.Copy(m.config, conf)
	return nil
}

func (m *mockProvider) Initialize(ctx context.Context) error {
	return nil
}

func (m *mockProvider) Config() map[string]any {
	m.mu.RLock()
	defer m.mu.RUnlock()
	config := make(map[string]any)
	maps.Copy(config, m.config)
	return config
}

func newMockProvider() *mockProvider {
	return &mockProvider{}
}

// Helper function to create a test core with all dependencies
func createTestCore(t *testing.T) *Core {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	router := NewRouter(log)

	// Create in-memory physical backend
	physical, _ := inmem.NewInmem(nil, nil)

	// Create and initialize barrier
	barrier, _ := NewAESGCMBarrier(physical)
	key, _ := barrier.GenerateKey(rand.Reader)
	barrier.Initialize(context.Background(), key, nil, rand.Reader)
	barrier.Unseal(context.Background(), key)

	core := &Core{
		logger:        log,
		router:        router,
		mounts:        NewMountTable(),
		mountsLock:    locking.DeadlockRWMutex{},
		authMethods:   make(map[string]auth.Factory),
		providers:     make(map[string]provider.Factory),
		roles:         authorize.NewRoleRegistry(),
		accessControl: authorize.NewAccessControl(),
		credSources:   cred.NewCredSourceRegistry(),
		auditManager:  &mockAuditManager{},
		physical:      physical,
		barrier:       barrier,
		activeContext: context.Background(),
		sealed:        new(uint32), // Initialize sealed flag (0 = unsealed)
		standby:       atomic.Bool{},
	}

	// Initialize namespace store
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)
	core.namespaceStore, _ = NewNamespaceStore(ctx, core, log)

	// Initialize token store
	core.tokenStore, _ = NewTokenStore(core, DefaultTokenStoreConfig())

	// Create and mount the system backend
	requiredMounts, _ := core.requiredMountTable(ctx)
	core.mounts = requiredMounts

	// Setup the mounts (this will create and mount the system backend)
	_ = core.setupMounts(ctx)

	return core
}
