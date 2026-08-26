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
	// rejectIf, when set and returning true for the handed material, makes MintFromSecret
	// fail with ErrChainedSecretRejected (simulating a downstream rejecting a stale secret).
	rejectIf func(SecretMaterial) bool
}

func (d *mockChainedDriver) MintCredential(_ context.Context, _ *CredSpec) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	return nil, nil, 0, "", fmt.Errorf("mockChainedDriver: direct mint not supported")
}

func (d *mockChainedDriver) MintFromSecret(_ context.Context, _ *CredSpec, material SecretMaterial) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	d.mintFromCalls.Add(1)
	d.lastMaterial = material
	if d.rejectIf != nil && d.rejectIf(material) {
		return nil, nil, 0, "", fmt.Errorf("downstream rejected the secret: %w", ErrChainedSecretRejected)
	}
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
	mintCalls  atomic.Int32
}

func (d *mockExchangeSecretDriver) MintCredential(_ context.Context, _ *CredSpec) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	return nil, nil, 0, "", fmt.Errorf("mockExchangeSecretDriver: exchange required")
}
func (d *mockExchangeSecretDriver) MintCredentialWithExchange(_ context.Context, _ *CredSpec, inputs *ExchangeInputs) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	d.mintCalls.Add(1)
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

// mockChainedExchangeDriver implements SourceDriver + ChainedExchangeMinter: it performs
// an "exchange" using BOTH the caller's exchange inputs and the fetched secret material.
type mockChainedExchangeDriver struct {
	driverType   string
	calls        atomic.Int32
	gotSubject   string
	lastMaterial SecretMaterial
	// rejectIf, when set and returning true for the handed material, fails with
	// ErrChainedSecretRejected (simulating an upstream invalid_client on a stale secret).
	rejectIf func(SecretMaterial) bool
	// incompleteIf, when set and returning true, fails with ErrChainedSecretIncomplete
	// before anything is sent (simulating a payload missing a half of a credential).
	incompleteIf func(SecretMaterial) bool
}

func (d *mockChainedExchangeDriver) MintCredential(_ context.Context, _ *CredSpec) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	return nil, nil, 0, "", fmt.Errorf("mockChainedExchangeDriver: exchange required")
}
func (d *mockChainedExchangeDriver) MintCredentialWithExchangeFromSecret(_ context.Context, _ *CredSpec, inputs *ExchangeInputs, material SecretMaterial) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	d.calls.Add(1)
	d.gotSubject = inputs.SubjectToken
	d.lastMaterial = material
	if d.rejectIf != nil && d.rejectIf(material) {
		return nil, nil, 0, "", fmt.Errorf("upstream rejected client auth: %w", ErrChainedSecretRejected)
	}
	if d.incompleteIf != nil && d.incompleteIf(material) {
		return nil, nil, 0, "", fmt.Errorf("payload missing a half: %w", ErrChainedSecretIncomplete)
	}
	return map[string]interface{}{"token": "exch:" + inputs.SubjectToken + ":" + material.Secret()}, nil, 0, "", nil
}
func (d *mockChainedExchangeDriver) Revoke(_ context.Context, _ string) error { return nil }
func (d *mockChainedExchangeDriver) Type() string                            { return d.driverType }
func (d *mockChainedExchangeDriver) Cleanup(_ context.Context) error         { return nil }

type mockChainedExchangeFactory struct{ driver *mockChainedExchangeDriver }

func (f *mockChainedExchangeFactory) Type() string { return f.driver.driverType }
func (f *mockChainedExchangeFactory) Create(_ map[string]string, _ *logger.GatedLogger) (SourceDriver, error) {
	return f.driver, nil
}
func (f *mockChainedExchangeFactory) ValidateConfig(_ map[string]string) error { return nil }
func (f *mockChainedExchangeFactory) SensitiveConfigFields() []string          { return nil }
func (f *mockChainedExchangeFactory) InferCredentialType(_ map[string]string) (string, error) {
	return "", fmt.Errorf("n/a")
}

// chainingEnv wires a secret source (leaseless, returns {token: THE-SECRET}) and a
// consumer source that implements ChainedSecretMinter.
type chainingEnv struct {
	manager                *Manager
	store                  *mockConfigStore
	secretDriver           *mockSourceDriver
	consumerDriver         *mockChainedDriver
	exchangeDriver         *mockExchangeSecretDriver
	exchangeConsumerDriver *mockChainedExchangeDriver
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

	exchangeConsumer := &mockChainedExchangeDriver{driverType: "exchangeconsumersrc"}
	require.NoError(t, driverRegistry.RegisterFactory(&mockChainedExchangeFactory{driver: exchangeConsumer}))

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
	// Consumer source whose driver is a ChainedExchangeMinter (token_exchange-shaped).
	store.AddSource(&CredSource{Name: "exchangeconsumersource", Type: "exchangeconsumersrc", Config: map[string]string{}})

	return &chainingEnv{manager: manager, store: store, secretDriver: secretFactory.driver, consumerDriver: consumer, exchangeDriver: exchange, exchangeConsumerDriver: exchangeConsumer}
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

// TestChaining_ExchangeConsumerRoutes: a chained consumer that ITSELF requests exchange
// (inputs != nil) routes to issueChainedExchange — the fetched secret becomes the mint
// material AND the consumer's own subject token drives the exchange.
func TestChaining_ExchangeConsumerRoutes(t *testing.T) {
	env := newChainingEnv(t)
	env.store.AddSpec(&CredSpec{Name: "exch-consumer", Type: TypeVaultToken, Source: "exchangeconsumersource",
		Config: map[string]string{ConfigSecretSpec: "secret-spec"}})

	ctx := createNamespaceContext()
	inputs := &ExchangeInputs{SubjectToken: "subj-user", SubjectTokenType: TokenTypeJWT}
	cred, err := env.manager.IssueCredential(ctx, chainCaller("tokA"), "exch-consumer", inputs)
	require.NoError(t, err)

	assert.Equal(t, int32(1), env.exchangeConsumerDriver.calls.Load(), "routed to the exchange-chaining mint")
	assert.Equal(t, "THE-SECRET", env.exchangeConsumerDriver.lastMaterial.Secret(), "fetched secret handed to the driver")
	assert.Equal(t, "subj-user", env.exchangeConsumerDriver.gotSubject, "consumer's own subject drove the exchange")
	assert.Equal(t, "exch:subj-user:THE-SECRET", cred.Data["token"])
}

// TestChaining_ExchangeConsumerFailsClosed: a chained consumer that requests exchange but
// whose driver is only a ChainedSecretMinter (not ChainedExchangeMinter) fails closed.
func TestChaining_ExchangeConsumerFailsClosed(t *testing.T) {
	env := newChainingEnv(t)
	env.store.AddSpec(&CredSpec{Name: "bad-exch", Type: TypeVaultToken, Source: "consumersource",
		Config: map[string]string{ConfigSecretSpec: "secret-spec"}})

	ctx := createNamespaceContext()
	inputs := &ExchangeInputs{SubjectToken: "s", SubjectTokenType: TokenTypeJWT}
	_, err := env.manager.IssueCredential(ctx, chainCaller("tokA"), "bad-exch", inputs)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not support secret_spec chaining with token exchange")
}

// TestChaining_ExchangeConsumerRetriesOnRejection: the exchange path inherits PR2's
// evict-and-retry — a cached client secret rejected upstream (invalid_client) is evicted
// and the exchange retries once with a fresh fetch.
func TestChaining_ExchangeConsumerRetriesOnRejection(t *testing.T) {
	env := newChainingEnv(t)
	// Secret driver returns "v1" then "v2" (a rotation at the source).
	var fetches atomic.Int32
	env.secretDriver.mintFunc = func(_ context.Context, _ *CredSpec) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
		val := "v1"
		if fetches.Add(1) > 1 {
			val = "v2"
		}
		return map[string]interface{}{"token": val}, nil, 0, "", nil
	}
	cfg := map[string]string{ConfigSecretSpec: "secret-spec", ConfigSecretCacheTTL: "30m"}
	env.store.AddSpec(&CredSpec{Name: "exch1", Type: TypeVaultToken, Source: "exchangeconsumersource", Config: cfg})
	env.store.AddSpec(&CredSpec{Name: "exch2", Type: TypeVaultToken, Source: "exchangeconsumersource", Config: cfg})

	ctx := createNamespaceContext()
	caller := chainCaller("tokA")
	inputs1 := &ExchangeInputs{SubjectToken: "s", SubjectTokenType: TokenTypeJWT}

	// Prime the cache with "v1".
	_, err := env.manager.IssueCredential(ctx, caller, "exch1", inputs1)
	require.NoError(t, err)
	require.Equal(t, int32(1), fetches.Load())

	// "v1" now stale: reject it. A second exchange consumer hits the cached "v1", is
	// rejected, evicts + re-fetches "v2", and succeeds.
	env.exchangeConsumerDriver.rejectIf = func(m SecretMaterial) bool { return m.Secret() == "v1" }
	inputs2 := &ExchangeInputs{SubjectToken: "s2", SubjectTokenType: TokenTypeJWT}
	cred, err := env.manager.IssueCredential(ctx, caller, "exch2", inputs2)
	require.NoError(t, err)
	assert.Equal(t, int32(2), fetches.Load(), "stale client secret evicted and re-fetched once")
	assert.Equal(t, "exch:s2:v2", cred.Data["token"], "exchange retried with the fresh secret")
}

// TestChaining_ExchangeConsumerRetriesOnIncompletePayload covers the migration case a
// rejection cannot: a cached payload that is missing a key the driver has since come to
// need. Nothing downstream refuses it — it never reaches a request — so without its own
// sentinel the entry would sit in the cache failing every mint for the whole TTL, and
// completing the secret at the source would have no effect until it expired.
func TestChaining_ExchangeConsumerRetriesOnIncompletePayload(t *testing.T) {
	env := newChainingEnv(t)
	// The referenced spec yields the old payload first, the completed one after.
	var fetches atomic.Int32
	env.secretDriver.mintFunc = func(_ context.Context, _ *CredSpec) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
		val := "old"
		if fetches.Add(1) > 1 {
			val = "completed"
		}
		return map[string]interface{}{"token": val}, nil, 0, "", nil
	}
	cfg := map[string]string{ConfigSecretSpec: "secret-spec", ConfigSecretCacheTTL: "30m"}
	env.store.AddSpec(&CredSpec{Name: "exch1", Type: TypeVaultToken, Source: "exchangeconsumersource", Config: cfg})
	env.store.AddSpec(&CredSpec{Name: "exch2", Type: TypeVaultToken, Source: "exchangeconsumersource", Config: cfg})

	ctx := createNamespaceContext()
	caller := chainCaller("tokA")

	// Prime the cache with the old payload.
	_, err := env.manager.IssueCredential(ctx, caller, "exch1", &ExchangeInputs{SubjectToken: "s", SubjectTokenType: TokenTypeJWT})
	require.NoError(t, err)
	require.Equal(t, int32(1), fetches.Load())

	// The driver now needs something the cached payload lacks. The second consumer hits
	// that entry, reports it incomplete, and the manager refetches once.
	env.exchangeConsumerDriver.incompleteIf = func(m SecretMaterial) bool { return m.Secret() == "old" }
	cred, err := env.manager.IssueCredential(ctx, caller, "exch2", &ExchangeInputs{SubjectToken: "s2", SubjectTokenType: TokenTypeJWT})
	require.NoError(t, err)
	assert.Equal(t, int32(2), fetches.Load(), "incomplete cached payload evicted and re-fetched once")
	assert.Equal(t, "exch:s2:completed", cred.Data["token"])
}

// TestChaining_IncompleteFreshPayloadIsNotRetried pins the other half of the contract:
// only a CACHED payload is worth refetching. Re-reading one just fetched would cost a
// second read to be told the same thing.
func TestChaining_IncompleteFreshPayloadIsNotRetried(t *testing.T) {
	env := newChainingEnv(t)
	var fetches atomic.Int32
	env.secretDriver.mintFunc = func(_ context.Context, _ *CredSpec) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
		fetches.Add(1)
		return map[string]interface{}{"token": "always-incomplete"}, nil, 0, "", nil
	}
	// No secret_cache_ttl: every mint fetches, so the material is never "from cache".
	env.store.AddSpec(&CredSpec{Name: "exch1", Type: TypeVaultToken, Source: "exchangeconsumersource",
		Config: map[string]string{ConfigSecretSpec: "secret-spec"}})
	env.exchangeConsumerDriver.incompleteIf = func(SecretMaterial) bool { return true }

	_, err := env.manager.IssueCredential(createNamespaceContext(), chainCaller("tokA"), "exch1",
		&ExchangeInputs{SubjectToken: "s", SubjectTokenType: TokenTypeJWT})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrChainedSecretIncomplete)
	assert.Equal(t, int32(1), fetches.Load(), "a freshly fetched payload is not re-fetched")
}

// exchangeChainCaller builds a Caller whose referenced-spec inputs carry a per-agent
// SubjectCacheIdentity (so the secret-cache key is per agent identity) and optionally a
// user principal + UserClaims (so a user-scoped referenced fetch keys per user).
func exchangeChainCaller(agentToken, agentIdentity, userToken string, userClaims map[string]string) Caller {
	c := Caller{
		TokenID:  agentToken,
		TokenTTL: time.Hour,
		ResolveInputs: func(_ context.Context, specName string) (*ExchangeInputs, error) {
			return &ExchangeInputs{
				SubjectCacheIdentity: agentIdentity,
				ResolveSubjectToken:  func(_ context.Context) (string, error) { return "subj-" + agentIdentity, nil },
				UserClaims:           userClaims,
			}, nil
		},
	}
	if userToken != "" {
		c.User = &UserContext{TokenID: userToken, TokenTTL: time.Hour}
	}
	return c
}

// TestChaining_CacheSharesAcrossConsumers: with secret_cache_ttl set, two consumer specs
// referencing the same secret-spec under one caller fetch the secret only ONCE (shared
// via the secret cache) — versus TestChaining_SecretNotCached's two fetches without a
// TTL. Also exercises the nil-inputs ("noexchange") cache-key path without panicking.
func TestChaining_CacheSharesAcrossConsumers(t *testing.T) {
	env := newChainingEnv(t)
	ttl := map[string]string{ConfigSecretSpec: "secret-spec", ConfigSecretCacheTTL: "30m"}
	env.store.AddSpec(&CredSpec{Name: "consumer1", Type: TypeVaultToken, Source: "consumersource", Config: ttl})
	env.store.AddSpec(&CredSpec{Name: "consumer2", Type: TypeVaultToken, Source: "consumersource", Config: ttl})

	ctx := createNamespaceContext()
	caller := chainCaller("tokA") // nil inputs -> "noexchange" key segment

	_, err := env.manager.IssueCredential(ctx, caller, "consumer1", nil)
	require.NoError(t, err)
	_, err = env.manager.IssueCredential(ctx, caller, "consumer2", nil)
	require.NoError(t, err)
	assert.Equal(t, int32(1), env.secretDriver.mintCalls.Load(), "secret_cache_ttl shares the fetched secret across consumers")
}

// TestChaining_CacheIsolatesPerAgent: even with caching on, two distinct agent
// identities never share a cached secret (the per-agent Fingerprint dimension). Two
// consumer specs referencing the same secret-spec would collapse to one fetch if the
// cache were agent-blind; keyed per agent they fetch twice.
func TestChaining_CacheIsolatesPerAgent(t *testing.T) {
	env := newChainingEnv(t)
	env.store.AddSpec(&CredSpec{Name: "exchange-secret", Type: TypeVaultToken, Source: "exchangesource", Config: map[string]string{}})
	cfg := map[string]string{ConfigSecretSpec: "exchange-secret", ConfigSecretCacheTTL: "30m"}
	env.store.AddSpec(&CredSpec{Name: "consumer1", Type: TypeVaultToken, Source: "consumersource", Config: cfg})
	env.store.AddSpec(&CredSpec{Name: "consumer2", Type: TypeVaultToken, Source: "consumersource", Config: cfg})

	ctx := createNamespaceContext()
	_, err := env.manager.IssueCredential(ctx, exchangeChainCaller("tokA", "agentA", "", nil), "consumer1", nil)
	require.NoError(t, err)
	_, err = env.manager.IssueCredential(ctx, exchangeChainCaller("tokB", "agentB", "", nil), "consumer2", nil)
	require.NoError(t, err)
	assert.Equal(t, int32(2), env.exchangeDriver.mintCalls.Load(), "distinct agents do not share a cached secret")
}

// TestChaining_CacheIsolatesPerUser (P0 regression): a user-scoped referenced fetch
// (UserClaims populated) is cached per user. The same user shares across consumer specs;
// a different user never receives the first user's secret.
func TestChaining_CacheIsolatesPerUser(t *testing.T) {
	env := newChainingEnv(t)
	env.store.AddSpec(&CredSpec{Name: "exchange-secret", Type: TypeVaultToken, Source: "exchangesource", Config: map[string]string{}})
	cfg := map[string]string{ConfigSecretSpec: "exchange-secret", ConfigSecretCacheTTL: "30m"}
	env.store.AddSpec(&CredSpec{Name: "consumer1", Type: TypeVaultToken, Source: "consumersource", Config: cfg})
	env.store.AddSpec(&CredSpec{Name: "consumer2", Type: TypeVaultToken, Source: "consumersource", Config: cfg})

	ctx := createNamespaceContext()
	claims := map[string]string{"sub": "alice"}

	// User A, two consumer specs, one agent -> shared within the user (one fetch).
	_, err := env.manager.IssueCredential(ctx, exchangeChainCaller("agentTok", "agentA", "userA", claims), "consumer1", nil)
	require.NoError(t, err)
	_, err = env.manager.IssueCredential(ctx, exchangeChainCaller("agentTok", "agentA", "userA", claims), "consumer2", nil)
	require.NoError(t, err)
	assert.Equal(t, int32(1), env.exchangeDriver.mintCalls.Load(), "same user shares the cached secret across consumers")

	// User B, same agent + secret-spec -> its own fetch (never served user A's secret).
	_, err = env.manager.IssueCredential(ctx, exchangeChainCaller("agentTok", "agentA", "userB", map[string]string{"sub": "bob"}), "consumer1", nil)
	require.NoError(t, err)
	assert.Equal(t, int32(2), env.exchangeDriver.mintCalls.Load(), "a different user fetches its own secret (no cross-user leak)")
}

// TestChaining_RetryEvictsStaleCachedSecret: when a cached secret is rejected downstream
// (ErrChainedSecretRejected), the manager evicts it and retries once with a fresh fetch.
func TestChaining_RetryEvictsStaleCachedSecret(t *testing.T) {
	env := newChainingEnv(t)
	// Secret driver returns "v1" first, "v2" after (a rotation at the source).
	var fetches atomic.Int32
	env.secretDriver.mintFunc = func(_ context.Context, _ *CredSpec) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
		n := fetches.Add(1)
		val := "v1"
		if n > 1 {
			val = "v2"
		}
		return map[string]interface{}{"token": val}, nil, 0, "", nil
	}
	cfg := map[string]string{ConfigSecretSpec: "secret-spec", ConfigSecretCacheTTL: "30m"}
	env.store.AddSpec(&CredSpec{Name: "consumer1", Type: TypeVaultToken, Source: "consumersource", Config: cfg})
	env.store.AddSpec(&CredSpec{Name: "consumer2", Type: TypeVaultToken, Source: "consumersource", Config: cfg})

	ctx := createNamespaceContext()
	caller := chainCaller("tokA")

	// Prime the cache with "v1".
	_, err := env.manager.IssueCredential(ctx, caller, "consumer1", nil)
	require.NoError(t, err)
	require.Equal(t, int32(1), fetches.Load())

	// Now "v1" is stale: reject it downstream. A second consumer (outer miss) hits the
	// cached "v1", is rejected, evicts + re-fetches "v2", and succeeds.
	env.consumerDriver.rejectIf = func(m SecretMaterial) bool { return m.Secret() == "v1" }
	cred, err := env.manager.IssueCredential(ctx, caller, "consumer2", nil)
	require.NoError(t, err)
	assert.Equal(t, int32(2), fetches.Load(), "stale cached secret evicted and re-fetched once")
	assert.Equal(t, "consumer-token:v2", cred.Data["token"], "retry minted from the fresh secret")
}

// TestChaining_NoRetryWhenSecretFresh: with caching off (ttl<=0) a downstream rejection
// is NOT retried — the just-fetched secret can't be stale, so re-fetching is pointless.
func TestChaining_NoRetryWhenSecretFresh(t *testing.T) {
	env := newChainingEnv(t)
	env.consumerDriver.rejectIf = func(SecretMaterial) bool { return true } // always reject
	env.store.AddSpec(&CredSpec{Name: "consumer", Type: TypeVaultToken, Source: "consumersource",
		Config: map[string]string{ConfigSecretSpec: "secret-spec"}}) // no secret_cache_ttl

	ctx := createNamespaceContext()
	_, err := env.manager.IssueCredential(ctx, chainCaller("tokA"), "consumer", nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrChainedSecretRejected)
	assert.Equal(t, int32(1), env.secretDriver.mintCalls.Load(), "no cache -> no retry (secret fetched once)")
	assert.Equal(t, int32(1), env.consumerDriver.mintFromCalls.Load(), "mint attempted once, not retried")
}

// TestChaining_NoRetryOnFreshFetchWithTTL: even with caching ON, a rejection of a
// freshly fetched secret (a cache MISS, fromCache=false) is not retried — only a cached
// (potentially stale) secret is. Guards the fromCache gate.
func TestChaining_NoRetryOnFreshFetchWithTTL(t *testing.T) {
	env := newChainingEnv(t)
	env.consumerDriver.rejectIf = func(SecretMaterial) bool { return true }
	env.store.AddSpec(&CredSpec{Name: "consumer", Type: TypeVaultToken, Source: "consumersource",
		Config: map[string]string{ConfigSecretSpec: "secret-spec", ConfigSecretCacheTTL: "30m"}})

	ctx := createNamespaceContext()
	_, err := env.manager.IssueCredential(ctx, chainCaller("tokA"), "consumer", nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrChainedSecretRejected)
	assert.Equal(t, int32(1), env.secretDriver.mintCalls.Load(), "fresh (miss) secret not retried, even with ttl>0")
	assert.Equal(t, int32(1), env.consumerDriver.mintFromCalls.Load(), "mint attempted once")
}

// TestChaining_CacheTTLSourceLevel: a source-level secret_cache_ttl enables caching for
// its consumer specs (no spec-level TTL), resolved spec-then-source.
func TestChaining_CacheTTLSourceLevel(t *testing.T) {
	env := newChainingEnv(t)
	env.store.AddSource(&CredSource{Name: "consumersource-cached", Type: "consumersrc",
		Config: map[string]string{ConfigSecretCacheTTL: "30m"}})
	env.store.AddSpec(&CredSpec{Name: "consumer1", Type: TypeVaultToken, Source: "consumersource-cached",
		Config: map[string]string{ConfigSecretSpec: "secret-spec"}})
	env.store.AddSpec(&CredSpec{Name: "consumer2", Type: TypeVaultToken, Source: "consumersource-cached",
		Config: map[string]string{ConfigSecretSpec: "secret-spec"}})

	ctx := createNamespaceContext()
	caller := chainCaller("tokA")
	_, err := env.manager.IssueCredential(ctx, caller, "consumer1", nil)
	require.NoError(t, err)
	_, err = env.manager.IssueCredential(ctx, caller, "consumer2", nil)
	require.NoError(t, err)
	assert.Equal(t, int32(1), env.secretDriver.mintCalls.Load(), "source-level secret_cache_ttl caches")
}

// TestChaining_CacheTTLSpecOptOut: a spec-level secret_cache_ttl "0" opts OUT of a
// source-level TTL (presence wins), so the secret is fetched every time.
func TestChaining_CacheTTLSpecOptOut(t *testing.T) {
	env := newChainingEnv(t)
	env.store.AddSource(&CredSource{Name: "consumersource-cached", Type: "consumersrc",
		Config: map[string]string{ConfigSecretCacheTTL: "30m"}})
	env.store.AddSpec(&CredSpec{Name: "consumer1", Type: TypeVaultToken, Source: "consumersource-cached",
		Config: map[string]string{ConfigSecretSpec: "secret-spec", ConfigSecretCacheTTL: "0"}})
	env.store.AddSpec(&CredSpec{Name: "consumer2", Type: TypeVaultToken, Source: "consumersource-cached",
		Config: map[string]string{ConfigSecretSpec: "secret-spec", ConfigSecretCacheTTL: "0"}})

	ctx := createNamespaceContext()
	caller := chainCaller("tokA")
	_, err := env.manager.IssueCredential(ctx, caller, "consumer1", nil)
	require.NoError(t, err)
	_, err = env.manager.IssueCredential(ctx, caller, "consumer2", nil)
	require.NoError(t, err)
	assert.Equal(t, int32(2), env.secretDriver.mintCalls.Load(), "spec-level 0 opts out of source TTL")
}

// TestChaining_CacheIsolatesPerRole: one principal authenticating under two roles
// must not share a cached secret, even though everything else about its identity
// matches.
//
// This is the cache that shares a fetch across an agent's sessions rather than
// asking the store again, so "agent identity" has to mean everything the store was
// shown. The assertion asserts warden_role and a downstream is invited to authorize
// on it, so the answer can differ per role — and the second role would otherwise
// receive a secret fetched under the first's authorization without the store ever
// being asked. Core folds the role into the cache identity for exactly this; here
// that shows up as the differing identity the two callers carry.
func TestChaining_CacheIsolatesPerRole(t *testing.T) {
	env := newChainingEnv(t)
	env.store.AddSpec(&CredSpec{Name: "exchange-secret", Type: TypeVaultToken, Source: "exchangesource", Config: map[string]string{}})
	cfg := map[string]string{ConfigSecretSpec: "exchange-secret", ConfigSecretCacheTTL: "30m"}
	env.store.AddSpec(&CredSpec{Name: "consumer1", Type: TypeVaultToken, Source: "consumersource", Config: cfg})
	env.store.AddSpec(&CredSpec{Name: "consumer2", Type: TypeVaultToken, Source: "consumersource", Config: cfg})

	ctx := createNamespaceContext()

	// The identities differ only by the role fragment core appends — same subject,
	// same audience, same everything else.
	const subject = "wid:ns1:auth_jwt_1:bot\x00https://sts.example/aud"
	reader := exchangeChainCaller("tokReader", subject+"\x00role=reader", "", nil)
	writer := exchangeChainCaller("tokWriter", subject+"\x00role=writer", "", nil)

	_, err := env.manager.IssueCredential(ctx, reader, "consumer1", nil)
	require.NoError(t, err)
	_, err = env.manager.IssueCredential(ctx, writer, "consumer2", nil)
	require.NoError(t, err)
	assert.Equal(t, int32(2), env.exchangeDriver.mintCalls.Load(),
		"a second role must fetch its own secret, not inherit the first role's")

	// The same role across sessions still shares — dropping that would trade this
	// bug for the loss of the cross-session sharing the cache exists to provide.
	_, err = env.manager.IssueCredential(ctx, exchangeChainCaller("tokReader2", subject+"\x00role=reader", "", nil), "consumer1", nil)
	require.NoError(t, err)
	assert.Equal(t, int32(2), env.exchangeDriver.mintCalls.Load(),
		"one role across two sessions must still share its cached secret")
}
