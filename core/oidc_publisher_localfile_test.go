package core

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLocalFilePublisher(t *testing.T) {
	dir := t.TempDir()
	p := &localFilePublisher{dir: dir}
	require.NoError(t, p.Publish(context.Background(), []byte(`{"issuer":"x"}`), []byte(`{"keys":[]}`)))

	disc, err := os.ReadFile(filepath.Join(dir, ".well-known", "openid-configuration"))
	require.NoError(t, err)
	assert.JSONEq(t, `{"issuer":"x"}`, string(disc))

	jwks, err := os.ReadFile(filepath.Join(dir, "oidc", "jwks"))
	require.NoError(t, err)
	assert.JSONEq(t, `{"keys":[]}`, string(jwks))
}
