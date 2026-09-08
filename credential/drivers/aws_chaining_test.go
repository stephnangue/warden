package drivers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/credential/types"
	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// chainStore is the smallest ConfigStoreAccessor that will serve a chain: specs
// and sources by name, and nothing else. The manager's own tests have a richer
// fake, but it lives in that package.
type chainStore struct {
	specs   map[string]*credential.CredSpec
	sources map[string]*credential.CredSource
}

func newChainStore() *chainStore {
	return &chainStore{
		specs:   map[string]*credential.CredSpec{},
		sources: map[string]*credential.CredSource{},
	}
}

func (s *chainStore) GetSpec(_ context.Context, name string) (*credential.CredSpec, error) {
	spec, ok := s.specs[name]
	if !ok {
		return nil, errors.New("spec not found")
	}
	return spec, nil
}

func (s *chainStore) GetSource(_ context.Context, name string) (*credential.CredSource, error) {
	src, ok := s.sources[name]
	if !ok {
		return nil, errors.New("source not found")
	}
	return src, nil
}

func (s *chainStore) PersistRotatedSpec(_ context.Context, _ *credential.CredSpec) error { return nil }

func (s *chainStore) ReloadSpec(ctx context.Context, name string) (*credential.CredSpec, error) {
	return s.GetSpec(ctx, name)
}

func chainNamespaceContext() context.Context {
	return namespace.ContextWithNamespace(context.Background(),
		&namespace.Namespace{ID: "chain-ns", Path: "chain/"})
}

// TestChaining_AWSSecretReadBacksAnAPIKeyConsumer drives a real chain through two
// real drivers: an aws secret_read spec is the referenced secret, and a static
// apikey spec carries none of its own and reads one field out of that payload.
//
// The unit tests either side of this cover the driver and the machinery
// separately; what this pins is that an aws source now satisfies what the
// chaining machinery demands of a referenced spec — chiefly that it vends a
// multi-field payload with no lease, which is refused outright if it carries one.
func TestChaining_AWSSecretReadBacksAnAPIKeyConsumer(t *testing.T) {
	stsSrv := newConcurrentSTSStub(t)

	var mu sync.Mutex
	var fetches int
	smSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		fetches++
		mu.Unlock()
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		_, _ = w.Write([]byte(`{"Name":"prod/datadog/keys","SecretString":"{\"api_key\":\"dd-key\",\"application_key\":\"dd-app-key\"}"}`))
	}))
	defer smSrv.Close()

	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})

	typeRegistry := credential.NewTypeRegistry()
	require.NoError(t, typeRegistry.Register(types.NewKeyValueCredType()))
	require.NoError(t, typeRegistry.Register(types.NewAPIKeyCredType()))

	driverRegistry := credential.NewDriverRegistry(log)
	require.NoError(t, driverRegistry.RegisterFactory(&AWSDriverFactory{}))
	require.NoError(t, driverRegistry.RegisterFactory(&StaticAPIKeyDriverFactory{}))

	store := newChainStore()
	store.sources["aws-fed"] = &credential.CredSource{
		Name: "aws-fed", Type: credential.SourceTypeAWS,
		Config: credential.NewConfig(map[string]string{
			"auth_method":             "oidc_federation",
			"region":                  "us-east-1",
			"sts_endpoint":            stsSrv.srv.URL,
			"secretsmanager_endpoint": smSrv.URL,
		}),
	}
	store.specs["datadog-keys-in-aws"] = &credential.CredSpec{
		Name: "datadog-keys-in-aws", Type: credential.TypeKeyValue, Source: "aws-fed",
		Config: credential.NewConfig(map[string]string{
			"mint_method":          "secret_read",
			"secret_id":            "prod/datadog/keys",
			"role_arn":             "arn:aws:iam::123456789012:role/WardenSecretsReader",
			"subject_token_source": "warden_identity",
		}),
	}
	store.sources["datadog-src"] = &credential.CredSource{
		Name: "datadog-src", Type: credential.SourceTypeAPIKey,
		Config: credential.NewConfig(map[string]string{"credential_fields": "application_key"}),
	}
	store.specs["datadog-cred"] = &credential.CredSpec{
		Name: "datadog-cred", Type: credential.TypeAPIKey, Source: "datadog-src",
		Config: credential.NewConfig(map[string]string{
			credential.ConfigSecretSpec:  "datadog-keys-in-aws",
			credential.ConfigSecretField: "api_key",
		}),
	}

	manager, err := credential.NewManager(typeRegistry, driverRegistry, store, log)
	require.NoError(t, err)

	caller := credential.Caller{
		TokenID:  "agent-token",
		TokenTTL: time.Hour,
		// Only the referenced spec requests an exchange; the consumer holds no
		// secret of its own and mints from the material.
		ResolveInputs: func(_ context.Context, specName string) (*credential.ExchangeInputs, error) {
			if specName != "datadog-keys-in-aws" {
				return nil, nil
			}
			return &credential.ExchangeInputs{
				SubjectToken:     "eyJ.warden.assertion",
				SubjectTokenType: credential.TokenTypeJWT,
			}, nil
		},
	}

	cred, err := manager.IssueCredential(chainNamespaceContext(), caller, "datadog-cred", nil)
	require.NoError(t, err)
	assert.Equal(t, credential.TypeAPIKey, cred.Type)
	assert.Equal(t, "dd-key", cred.Data["api_key"],
		"the consumer must carry the field its secret_field named")

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, 1, fetches, "one issuance must read the stored secret once")
}
