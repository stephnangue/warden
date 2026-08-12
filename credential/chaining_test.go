package credential

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stephnangue/warden/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockChainedDriver implements SourceDriver + ChainedSecretMinter. It records the
// material handed to MintFromSecret and echoes the selected secret into a token.
type mockChainedDriver struct {
	driverType    string
	mintFromCalls atomic.Int32
	lastMaterial  SecretMaterial
}

func (d *mockChainedDriver) MintCredential(_ context.Context, _ *CredSpec) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	return nil, nil, 0, "", fmt.Errorf("mockChainedDriver: direct mint not supported")
}

func (d *mockChainedDriver) MintFromSecret(_ context.Context, _ *CredSpec, material SecretMaterial) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	d.mintFromCalls.Add(1)
	d.lastMaterial = material
	return map[string]interface{}{"token": "consumer-token:" + material.Secret()}, nil, 0, "", nil
}

func (d *mockChainedDriver) Revoke(_ context.Context, _ string) error { return nil }
func (d *mockChainedDriver) Type() string                            { return d.driverType }
func (d *mockChainedDriver) Cleanup(_ context.Context) error         { return nil }

type mockChainedFactory struct{ driver *mockChainedDriver }

func (f *mockChainedFactory) Type() string { return f.driver.driverType }
func (f *mockChainedFactory) Create(_ map[string]string, _ *logger.GatedLogger) (SourceDriver, error) {
	return f.driver, nil
}
func (f *mockChainedFactory) ValidateConfig(_ map[string]string) error   { return nil }
func (f *mockChainedFactory) SensitiveConfigFields() []string            { return nil }
func (f *mockChainedFactory) InferCredentialType(_ map[string]string) (string, error) {
	return "", fmt.Errorf("n/a")
}

// mockExchangeSecretDriver is a referenced-spec driver that consumes exchange inputs
// (ExchangeMinter). It records the subject/actor tokens it received so a test can
// assert they were materialized before the referenced mint.
type mockExchangeSecretDriver struct {
	driverType string
	gotSubject string
	gotActor   string
}

func (d *mockExchangeSecretDriver) MintCredential(_ context.Context, _ *CredSpec) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	return nil, nil, 0, "", fmt.Errorf("mockExchangeSecretDriver: exchange required")
}
func (d *mockExchangeSecretDriver) MintCredentialWithExchange(_ context.Context, _ *CredSpec, inputs *ExchangeInputs) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	d.gotSubject = inputs.SubjectToken
	d.gotActor = inputs.ActorToken
	return map[string]interface{}{"token": "SECRET-" + inputs.SubjectToken}, nil, 0, "", nil
}
func (d *mockExchangeSecretDriver) Revoke(_ context.Context, _ string) error { return nil }
func (d *mockExchangeSecretDriver) Type() string                            { return d.driverType }
func (d *mockExchangeSecretDriver) Cleanup(_ context.Context) error         { return nil }

type mockExchangeSecretFactory struct{ driver *mockExchangeSecretDriver }

func (f *mockExchangeSecretFactory) Type() string { return f.driver.driverType }
func (f *mockExchangeSecretFactory) Create(_ map[string]string, _ *logger.GatedLogger) (SourceDriver, error) {
	return f.driver, nil
}
func (f *mockExchangeSecretFactory) ValidateConfig(_ map[string]string) error { return nil }
func (f *mockExchangeSecretFactory) SensitiveConfigFields() []string          { return nil }
func (f *mockExchangeSecretFactory) InferCredentialType(_ map[string]string) (string, error) {
	return "", fmt.Errorf("n/a")
}

// chainingEnv wires a secret source (leaseless, returns {token: THE-SECRET}) and a
// consumer source that implements ChainedSecretMinter.
type chainingEnv struct {
	manager        *Manager
	store          *mockConfigStore
	secretDriver   *mockSourceDriver
	consumerDriver *mockChainedDriver
	exchangeDriver *mockExchangeSecretDriver
}

func newChainingEnv(t *testing.T) *chainingEnv {
	t.Helper()
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})

	typeRegistry := NewTypeRegistry()
	require.NoError(t, typeRegistry.Register(newMockCredentialType(TypeVaultToken, CategoryAPI)))

	driverRegistry := NewDriverRegistry(nil)

	secretFactory := newMockSourceDriverFactory("secretsrc")
	// Leaseless secret material (kv-read shape): no lease, static.
	secretFactory.driver.mintFunc = func(_ context.Context, _ *CredSpec) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
		return map[string]interface{}{"token": "THE-SECRET"}, nil, 0, "", nil
	}
	require.NoError(t, driverRegistry.RegisterFactory(secretFactory))

	consumer := &mockChainedDriver{driverType: "consumersrc"}
	require.NoError(t, driverRegistry.RegisterFactory(&mockChainedFactory{driver: consumer}))

	exchange := &mockExchangeSecretDriver{driverType: "exchangesrc"}
	require.NoError(t, driverRegistry.RegisterFactory(&mockExchangeSecretFactory{driver: exchange}))

	store := newMockConfigStore()
	manager, err := NewManager(typeRegistry, driverRegistry, store, log)
	require.NoError(t, err)

	// Secret source + spec.
	store.AddSource(&CredSource{Name: "secretsource", Type: "secretsrc", Config: map[string]string{}})
	store.AddSpec(&CredSpec{Name: "secret-spec", Type: TypeVaultToken, Source: "secretsource", Config: map[string]string{}})
	// Consumer source.
	store.AddSource(&CredSource{Name: "consumersource", Type: "consumersrc", Config: map[string]string{}})
	// Exchange-consuming secret source (for materialization tests).
	store.AddSource(&CredSource{Name: "exchangesource", Type: "exchangesrc", Config: map[string]string{}})

	return &chainingEnv{manager: manager, store: store, secretDriver: secretFactory.driver, consumerDriver: consumer, exchangeDriver: exchange}
}

// caller with a no-op ResolveInputs (the referenced secret-spec does not request
// exchange in these tests, so nil inputs are correct).
func chainCaller(tokenID string) Caller {
	return Caller{
		TokenID:  tokenID,
		TokenTTL: time.Hour,
		ResolveInputs: func(_ context.Context, _ string) (*ExchangeInputs, error) {
			return nil, nil
		},
	}
}

func TestChaining_MaterialFlowsToConsumer(t *testing.T) {
	env := newChainingEnv(t)
	env.store.AddSpec(&CredSpec{Name: "consumer", Type: TypeVaultToken, Source: "consumersource",
		Config: map[string]string{ConfigSecretSpec: "secret-spec"}})

	ctx := createNamespaceContext()
	cred, err := env.manager.IssueCredential(ctx, chainCaller("tokA"), "consumer", nil)
	require.NoError(t, err)

	assert.Equal(t, "THE-SECRET", env.consumerDriver.lastMaterial.Secret(), "consumer received the fetched secret")
	assert.Equal(t, "consumer-token:THE-SECRET", cred.Data["token"], "consumer minted from the material")
	assert.Equal(t, int32(1), env.secretDriver.mintCalls.Load(), "secret fetched once")
}

// TestChaining_SecretNotCached proves the fetched secret is not cached: a second
// consumer spec referencing the SAME secret-spec triggers a fresh secret fetch
// (its own outer-cache miss), rather than reusing a cached secret.
func TestChaining_SecretNotCached(t *testing.T) {
	env := newChainingEnv(t)
	env.store.AddSpec(&CredSpec{Name: "consumer1", Type: TypeVaultToken, Source: "consumersource",
		Config: map[string]string{ConfigSecretSpec: "secret-spec"}})
	env.store.AddSpec(&CredSpec{Name: "consumer2", Type: TypeVaultToken, Source: "consumersource",
		Config: map[string]string{ConfigSecretSpec: "secret-spec"}})

	ctx := createNamespaceContext()
	caller := chainCaller("tokA")

	_, err := env.manager.IssueCredential(ctx, caller, "consumer1", nil)
	require.NoError(t, err)
	// Same caller + same outer spec: outer cache hit, no new secret fetch.
	_, err = env.manager.IssueCredential(ctx, caller, "consumer1", nil)
	require.NoError(t, err)
	assert.Equal(t, int32(1), env.secretDriver.mintCalls.Load(), "outer cache hit: secret not re-fetched")

	// Different outer spec, same secret-spec: outer miss re-fetches the secret,
	// proving the secret itself was never cached/shared.
	_, err = env.manager.IssueCredential(ctx, caller, "consumer2", nil)
	require.NoError(t, err)
	assert.Equal(t, int32(2), env.secretDriver.mintCalls.Load(), "secret re-read on a separate outer miss")
}

// TestChaining_PerCaller proves per-caller isolation: a different caller re-fetches
// the secret (its own outer key), never reusing another caller's fetch.
func TestChaining_PerCaller(t *testing.T) {
	env := newChainingEnv(t)
	env.store.AddSpec(&CredSpec{Name: "consumer", Type: TypeVaultToken, Source: "consumersource",
		Config: map[string]string{ConfigSecretSpec: "secret-spec"}})

	ctx := createNamespaceContext()
	_, err := env.manager.IssueCredential(ctx, chainCaller("tokA"), "consumer", nil)
	require.NoError(t, err)
	_, err = env.manager.IssueCredential(ctx, chainCaller("tokB"), "consumer", nil)
	require.NoError(t, err)
	assert.Equal(t, int32(2), env.secretDriver.mintCalls.Load(), "each caller fetches its own secret")
}

func TestChaining_DepthGuard(t *testing.T) {
	env := newChainingEnv(t)
	// secret-spec-2 is the terminal secret; secret-spec-1 illegally chains to it.
	env.store.AddSpec(&CredSpec{Name: "secret-spec-2", Type: TypeVaultToken, Source: "secretsource", Config: map[string]string{}})
	env.store.AddSpec(&CredSpec{Name: "secret-spec-1", Type: TypeVaultToken, Source: "secretsource",
		Config: map[string]string{ConfigSecretSpec: "secret-spec-2"}})
	env.store.AddSpec(&CredSpec{Name: "consumer", Type: TypeVaultToken, Source: "consumersource",
		Config: map[string]string{ConfigSecretSpec: "secret-spec-1"}})

	ctx := createNamespaceContext()
	_, err := env.manager.IssueCredential(ctx, chainCaller("tokA"), "consumer", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "max depth")
}

// TestChaining_FailsClosedNonChainedDriver: a consumer whose driver does not
// implement ChainedSecretMinter fails closed.
func TestChaining_FailsClosedNonChainedDriver(t *testing.T) {
	env := newChainingEnv(t)
	// "secretsource" driver (mockSourceDriver) does not implement ChainedSecretMinter.
	env.store.AddSpec(&CredSpec{Name: "bad-consumer", Type: TypeVaultToken, Source: "secretsource",
		Config: map[string]string{ConfigSecretSpec: "secret-spec"}})

	ctx := createNamespaceContext()
	_, err := env.manager.IssueCredential(ctx, chainCaller("tokA"), "bad-consumer", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not support secret_spec chaining")
}

// TestChaining_LeaselessBackstop: a referenced secret-spec that returns a lease is
// rejected (config-drift backstop).
func TestChaining_LeaselessBackstop(t *testing.T) {
	env := newChainingEnv(t)
	// Make the secret driver return a lease.
	env.secretDriver.mintFunc = func(_ context.Context, _ *CredSpec) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
		return map[string]interface{}{"token": "THE-SECRET"}, nil, time.Hour, "lease-xyz", nil
	}
	env.store.AddSpec(&CredSpec{Name: "consumer", Type: TypeVaultToken, Source: "consumersource",
		Config: map[string]string{ConfigSecretSpec: "secret-spec"}})

	ctx := createNamespaceContext()
	_, err := env.manager.IssueCredential(ctx, chainCaller("tokA"), "consumer", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "static/leaseless")
}

// TestChaining_SecretFieldSelection covers multi-key payloads: an explicit
// secret_field selects the value; a single-key payload auto-detects.
func TestChaining_SecretFieldSelection(t *testing.T) {
	env := newChainingEnv(t)
	env.secretDriver.mintFunc = func(_ context.Context, _ *CredSpec) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
		return map[string]interface{}{"alpha": "A", "beta": "B"}, nil, 0, "", nil
	}
	env.store.AddSpec(&CredSpec{Name: "consumer", Type: TypeVaultToken, Source: "consumersource",
		Config: map[string]string{ConfigSecretSpec: "secret-spec", ConfigSecretField: "beta"}})

	ctx := createNamespaceContext()
	_, err := env.manager.IssueCredential(ctx, chainCaller("tokA"), "consumer", nil)
	require.NoError(t, err)
	assert.Equal(t, "B", env.consumerDriver.lastMaterial.Secret(), "secret_field selects the value")
	assert.Equal(t, "A", env.consumerDriver.lastMaterial.Data["alpha"], "full payload available for multi-secret drivers")
}

// TestChaining_MaterializesSubjectAndActor proves issueChained materializes BOTH the
// lazy subject and actor tokens before the referenced (exchange) mint — otherwise the
// driver would see empty tokens (subject fails closed; actor silently dropped).
func TestChaining_MaterializesSubjectAndActor(t *testing.T) {
	env := newChainingEnv(t)
	env.store.AddSpec(&CredSpec{Name: "exchange-secret", Type: TypeVaultToken, Source: "exchangesource", Config: map[string]string{}})
	env.store.AddSpec(&CredSpec{Name: "consumer", Type: TypeVaultToken, Source: "consumersource",
		Config: map[string]string{ConfigSecretSpec: "exchange-secret"}})

	caller := Caller{
		TokenID:  "tokA",
		TokenTTL: time.Hour,
		ResolveInputs: func(_ context.Context, specName string) (*ExchangeInputs, error) {
			// Inputs for the referenced spec, with lazy subject + actor resolvers
			// (as core would build for warden_identity subject + actor).
			return &ExchangeInputs{
				SubjectCacheIdentity: "id:" + specName,
				ResolveSubjectToken:  func(_ context.Context) (string, error) { return "resolved-subject", nil },
				ActorCacheIdentity:   "actor:" + specName,
				ResolveActorToken:    func(_ context.Context) (string, error) { return "resolved-actor", nil },
			}, nil
		},
	}

	ctx := createNamespaceContext()
	_, err := env.manager.IssueCredential(ctx, caller, "consumer", nil)
	require.NoError(t, err)
	assert.Equal(t, "resolved-subject", env.exchangeDriver.gotSubject, "subject token materialized before referenced mint")
	assert.Equal(t, "resolved-actor", env.exchangeDriver.gotActor, "actor token materialized before referenced mint")
	assert.Equal(t, "SECRET-resolved-subject", env.consumerDriver.lastMaterial.Secret())
}

// TestChaining_RequiresCallerContext: a nil ResolveInputs (non-request path) fails
// closed rather than minting the referenced spec without a caller.
func TestChaining_RequiresCallerContext(t *testing.T) {
	env := newChainingEnv(t)
	env.store.AddSpec(&CredSpec{Name: "consumer", Type: TypeVaultToken, Source: "consumersource",
		Config: map[string]string{ConfigSecretSpec: "secret-spec"}})

	ctx := createNamespaceContext()
	caller := Caller{TokenID: "tokA", TokenTTL: time.Hour} // ResolveInputs nil
	_, err := env.manager.IssueCredential(ctx, caller, "consumer", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "requires a request caller context")
}
