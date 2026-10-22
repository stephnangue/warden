package core

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// legacyServiceTokenID computes the ID a token value was stored under before
// the current prefixes, independently of the code under test.
func legacyServiceTokenID(value string) string {
	h := sha256.Sum256([]byte(value))
	return "wtkn_" + hex.EncodeToString(h[:])[:32]
}

func TestServiceTokenType_Metadata(t *testing.T) {
	meta := (&ServiceTokenType{}).Metadata()
	assert.Equal(t, "service_token", meta.Name)
	assert.Equal(t, TypeServiceToken, meta.Name)
	assert.Equal(t, "wds_", meta.IDPrefix)
	assert.Equal(t, "wds.", meta.ValuePrefix)
	assert.Equal(t, "cws.", meta.LegacyValuePrefix)
}

// A new service token is wds. followed by 64 random characters, stored under
// wds_ followed by the 32-hex hash of its value.
func TestServiceTokenType_Generate(t *testing.T) {
	st := &ServiceTokenType{}
	entry := &TokenEntry{}
	out, err := st.Generate(context.Background(), &AuthData{}, entry)
	require.NoError(t, err)

	value := out["token"]
	assert.Regexp(t, `^wds\.`, value)
	assert.Len(t, value, 68)
	assert.Equal(t, value, entry.Data["token"])
	assert.True(t, st.ValidateValue(value))

	h := sha256.Sum256([]byte(value))
	assert.Equal(t, "wds_"+hex.EncodeToString(h[:])[:32], st.ComputeID(value))

	again, err := st.Generate(context.Background(), &AuthData{}, &TokenEntry{})
	require.NoError(t, err)
	assert.NotEqual(t, value, again["token"])
}

// A legacy value is recognised and computes the ID it was stored under; a new
// value never takes the legacy format.
func TestServiceTokenType_LegacyValues(t *testing.T) {
	st := &ServiceTokenType{}
	legacy := "cws." + strings.Repeat("a", 64)

	assert.True(t, st.ValidateValue(legacy))
	assert.Equal(t, legacyServiceTokenID(legacy), st.ComputeID(legacy))
	for _, bad := range []string{"cws.short", "wds.short", "xyz." + strings.Repeat("a", 64), "", "wds." + strings.Repeat("a", 65)} {
		assert.False(t, st.ValidateValue(bad), bad)
	}
	// A custom dev-mode root value takes the current ID prefix.
	assert.Regexp(t, `^wds_[0-9a-f]{32}$`, st.ComputeID("my-dev-token"))

	reg := NewTokenTypeRegistry()
	require.NoError(t, reg.Register(st))
	for _, value := range []string{legacy, "wds." + strings.Repeat("b", 64)} {
		detected, err := reg.DetectType(value)
		require.NoError(t, err, value)
		assert.Equal(t, "service_token", detected.Metadata().Name, value)
	}
	_, err := reg.GetByName("warden_token")
	assert.ErrorIs(t, err, ErrTypeNotFound, "no alias for the old type name")
}

// A fresh root token is a service token in the current format.
func TestServiceToken_FreshRoot(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	root, err := core.tokenStore.GenerateRootToken()
	require.NoError(t, err)
	assert.Regexp(t, `^wds\.`, root)
	assert.Len(t, root, 68)

	entry, err := core.LookupToken(ctx, root)
	require.NoError(t, err)
	assert.Equal(t, "service_token", entry.Type)
	assert.Regexp(t, `^wds_[0-9a-f]{32}$`, entry.ID)
	assert.Equal(t, []string{"root"}, entry.Policies)
	assert.Equal(t, entry.ID, core.tokenStore.rootTokenManager.GetCurrentRootTokenID())
}

// A root token stored before the current prefixes (type warden_token, value
// cws.<64>, ID wtkn_<hash>) survives a restart: it is loaded as the root
// token, resolves under the ID it was stored with, and authorizes a request.
// Nothing about it is rewritten.
func TestServiceToken_LegacyRootAfterRestart(t *testing.T) {
	c := createTestCore(t)
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	value := "cws." + strings.Repeat("Q", 64)
	accessor, err := generateAccessor()
	require.NoError(t, err)
	stored := &TokenEntry{
		ID:            legacyServiceTokenID(value),
		Accessor:      accessor,
		Type:          "warden_token",
		NamespaceID:   namespace.RootNamespaceID,
		NamespacePath: namespace.RootNamespace.Path,
		CreatedAt:     time.Now().Add(-24 * time.Hour),
		PrincipalID:   namespace.RootNamespaceUUID,
		Policies:      []string{"root"},
		Data:          map[string]string{"token": value},
	}
	require.NoError(t, c.tokenStore.persistToken(stored))
	c.tokenStore.Close()

	// Restart: a new token store loads what storage holds.
	ts, err := NewTokenStore(c, nil)
	require.NoError(t, err)
	c.tokenStore = ts
	defer ts.Close()
	require.NoError(t, ts.LoadFromStorage(ctx))

	assert.True(t, ts.rootTokenManager.IsRootToken(value), "recognised as the root token whatever its type name")
	assert.Equal(t, stored.ID, ts.rootTokenManager.GetCurrentRootTokenID())

	entry, err := c.LookupToken(ctx, value)
	require.NoError(t, err)
	assert.Equal(t, stored.ID, entry.ID, "looked up under the ID it was stored with")
	assert.Equal(t, "warden_token", entry.Type, "nothing is rewritten")
	assert.False(t, ts.IsTransparentType(entry.Type))

	principal, err := ts.ResolveToken(ctx, value)
	require.NoError(t, err)
	assert.Equal(t, namespace.RootNamespaceUUID, principal)

	resp := roleHTTP(t, c, value, http.MethodPost, "/v1/sys/roles/deploy", map[string]any{"policies": []string{"deploy"}})
	assert.Equal(t, http.StatusCreated, resp.StatusCode, "%v", resp.Err)

	// The legacy value never resolves under the current ID prefix, and a
	// look-alike of the new format is a different token.
	_, err = c.LookupToken(ctx, "wds."+strings.Repeat("Q", 64))
	assert.Error(t, err)
}
