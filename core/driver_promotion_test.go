package core

import (
	"context"
	"testing"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/logger"
	"github.com/stretchr/testify/require"
)

// versionDriver reports the "version" of the config it was built from.
type versionDriver struct{ version string }

func (d *versionDriver) MintCredential(context.Context, *credential.CredSpec) (map[string]any, map[string]any, time.Duration, string, error) {
	return map[string]any{"version": d.version}, nil, 0, "", nil
}
func (d *versionDriver) Revoke(context.Context, string) error { return nil }
func (d *versionDriver) Type() string                         { return "versioned" }
func (d *versionDriver) Cleanup(context.Context) error        { return nil }

type versionFactory struct{}

func (versionFactory) Type() string                                          { return "versioned" }
func (versionFactory) ValidateConfig(credential.Config) error                { return nil }
func (versionFactory) SensitiveConfigFields() []string                       { return nil }
func (versionFactory) StoredSecrets(credential.Config) []string              { return nil }
func (versionFactory) InferCredentialType(credential.Config) (string, error) { return "", nil }
func (versionFactory) Create(config credential.Config, _ *logger.GatedLogger) (credential.SourceDriver, error) {
	return &versionDriver{version: config.Get("version")}, nil
}

// A node that steps down and later becomes active again must not mint with a
// driver built from config another node replaced while it was standby. The
// registry outlives the active term; before teardown closed its instances, the
// returning node kept the old driver — and the old secret — until restart.
func TestHA_DriverRebuiltAfterRepromotion(t *testing.T) {
	origSleep := manualStepDownSleepPeriod
	manualStepDownSleepPeriod = 100 * time.Millisecond
	defer func() { manualStepDownSleepPeriod = origSleep }()

	active, standby, core1, core2, _ := setupTwoNodeHA(t)
	defer core1.Shutdown()
	defer core2.Shutdown()
	for _, c := range []*Core{core1, core2} {
		require.NoError(t, c.credentialDriverRegistry.RegisterFactory(versionFactory{}))
	}
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	// The first node builds a driver from version 1.
	require.NoError(t, active.credConfigStore.CreateSource(ctx, &credential.CredSource{
		Name: "src", Type: "versioned", Config: credential.NewConfig(map[string]string{"version": "1"}),
	}))
	driver, err := active.credentialManager.GetOrCreateDriver(ctx, "src")
	require.NoError(t, err)
	require.Equal(t, "1", driver.(*versionDriver).version)
	first := active

	// It steps down; the other node, now active, moves the source to version 2.
	require.NoError(t, first.StepDown(nil))
	second := waitForActiveNode(t, []*Core{standby}, 10*time.Second)
	require.NotNil(t, second)
	src, err := second.credConfigStore.GetSource(ctx, "src")
	require.NoError(t, err)
	updated := *src
	updated.Config = credential.NewConfig(map[string]string{"version": "2"})
	require.NoError(t, second.credConfigStore.UpdateSource(ctx, &updated))

	// It steps down in turn, and the first node takes over again.
	require.NoError(t, second.StepDown(nil))
	require.NotNil(t, waitForActiveNode(t, []*Core{first}, 10*time.Second))

	driver, err = first.credentialManager.GetOrCreateDriver(ctx, "src")
	require.NoError(t, err)
	require.Equal(t, "2", driver.(*versionDriver).version, "the returning node must build from current config")
}
