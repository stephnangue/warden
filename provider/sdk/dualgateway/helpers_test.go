package dualgateway

import (
	"context"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
	"github.com/stretchr/testify/require"
)

// --- in-memory storage mock ---

type inmemStorage struct {
	mu   sync.RWMutex
	data map[string]*sdklogical.StorageEntry
}

func newInmemStorage() *inmemStorage {
	return &inmemStorage{data: make(map[string]*sdklogical.StorageEntry)}
}

func (s *inmemStorage) List(ctx context.Context, prefix string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var keys []string
	for k := range s.data {
		keys = append(keys, k)
	}
	return keys, nil
}

func (s *inmemStorage) ListPage(ctx context.Context, prefix string, after string, limit int) ([]string, error) {
	return s.List(ctx, prefix)
}

func (s *inmemStorage) Get(ctx context.Context, key string) (*sdklogical.StorageEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.data[key], nil
}

func (s *inmemStorage) Put(ctx context.Context, entry *sdklogical.StorageEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[entry.Key] = entry
	return nil
}

func (s *inmemStorage) Delete(ctx context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, key)
	return nil
}

// --- logger helper ---

func createTestLogger() *logger.GatedLogger {
	config := &logger.Config{
		Level:   logger.TraceLevel,
		Format:  logger.DefaultFormat,
		Outputs: []io.Writer{io.Discard},
	}
	gl, _ := logger.NewGatedLogger(config, logger.GatedWriterConfig{
		Underlying:   io.Discard,
		InitialState: logger.GateOpen,
	})
	return gl
}

// --- field data helper ---

func makeFieldData(path *framework.Path, raw map[string]interface{}) *framework.FieldData {
	return &framework.FieldData{
		Raw:    raw,
		Schema: path.Fields,
	}
}

// --- test specs ---

// headerAuthSpec mimics Scaleway: injects a custom header, doesn't strip Authorization.
var headerAuthSpec = &ProviderSpec{
	Name:           "testprovider",
	HelpText:       "test provider help",
	CredentialType: "test_keys",
	DefaultURL:     "https://api.test.com",
	URLConfigKey:   "test_url",
	DefaultTimeout: 30 * time.Second,
	UserAgent:      "warden-test-proxy",
	APIAuth: APIAuthStrategy{
		HeaderName:        "X-Auth-Token",
		HeaderValueFormat: "%s",
		CredentialField:   "secret_key",
	},
	S3Endpoint: func(_ map[string]any, region string) string {
		return fmt.Sprintf("s3.%s.test.cloud", region)
	},
}

// bearerAuthSpec mimics OVH: injects Authorization: Bearer, strips incoming Authorization.
var bearerAuthSpec = &ProviderSpec{
	Name:           "testbearer",
	HelpText:       "test bearer provider help",
	CredentialType: "bearer_keys",
	DefaultURL:     "https://api.bearer.com/1.0",
	URLConfigKey:   "bearer_url",
	DefaultTimeout: 30 * time.Second,
	UserAgent:      "warden-bearer-proxy",
	APIAuth: APIAuthStrategy{
		HeaderName:         "Authorization",
		HeaderValueFormat:  "Bearer %s",
		CredentialField:    "api_token",
		StripAuthorization: true,
	},
	S3Endpoint: func(_ map[string]any, region string) string {
		return fmt.Sprintf("s3.%s.bearer.net", region)
	},
}

// --- backend creation helper ---

func createBackend(t *testing.T, spec *ProviderSpec) *dualgatewayBackend {
	t.Helper()
	factory := NewFactory(spec)
	b, err := factory(context.Background(), &logical.BackendConfig{
		StorageView: newInmemStorage(),
		Logger:      createTestLogger(),
	})
	require.NoError(t, err)
	return b.(*dualgatewayBackend)
}
