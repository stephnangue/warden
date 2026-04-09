package drivers

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testDriverLogger() *logger.GatedLogger {
	config := &logger.Config{
		Level:   logger.ErrorLevel,
		Format:  logger.JSONFormat,
		Outputs: []io.Writer{io.Discard},
	}
	gateConfig := logger.GatedWriterConfig{
		Underlying: io.Discard,
	}
	gl, _ := logger.NewGatedLogger(config, gateConfig)
	return gl
}

// =============================================================================
// LocalDriver Tests
// =============================================================================

func TestLocalDriverFactory_Type(t *testing.T) {
	f := &LocalDriverFactory{}
	assert.Equal(t, credential.SourceTypeLocal, f.Type())
}

func TestLocalDriverFactory_ValidateConfig(t *testing.T) {
	f := &LocalDriverFactory{}
	assert.NoError(t, f.ValidateConfig(map[string]string{}))
}

func TestLocalDriverFactory_SensitiveConfigFields(t *testing.T) {
	f := &LocalDriverFactory{}
	assert.Empty(t, f.SensitiveConfigFields())
}

func TestLocalDriverFactory_Create(t *testing.T) {
	f := &LocalDriverFactory{}
	driver, err := f.Create(map[string]string{}, testDriverLogger())
	require.NoError(t, err)
	assert.Equal(t, credential.SourceTypeLocal, driver.Type())
}

func TestLocalDriverFactory_InferCredentialType(t *testing.T) {
	f := &LocalDriverFactory{}
	_, err := f.InferCredentialType(map[string]string{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "specify type explicitly")
}

func TestLocalDriver_MintCredential(t *testing.T) {
	f := &LocalDriverFactory{}
	driver, _ := f.Create(map[string]string{}, testDriverLogger())

	spec := &credential.CredSpec{
		Name: "test",
		Config: map[string]string{
			"username": "admin",
			"password": "secret",
		},
	}

	data, ttl, leaseID, err := driver.MintCredential(context.Background(), spec)
	require.NoError(t, err)
	assert.Equal(t, "admin", data["username"])
	assert.Equal(t, "secret", data["password"])
	assert.Equal(t, time.Duration(0), ttl)
	assert.Empty(t, leaseID)
}

func TestLocalDriver_Revoke(t *testing.T) {
	f := &LocalDriverFactory{}
	driver, _ := f.Create(map[string]string{}, testDriverLogger())
	assert.NoError(t, driver.Revoke(context.Background(), "lease"))
}

func TestLocalDriver_Cleanup(t *testing.T) {
	f := &LocalDriverFactory{}
	driver, _ := f.Create(map[string]string{}, testDriverLogger())
	assert.NoError(t, driver.Cleanup(context.Background()))
}

// =============================================================================
// RegisterBuiltinDrivers Tests
// =============================================================================
