package core

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/openbao/openbao/helper/namespace"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCryptoTokenType_Metadata(t *testing.T) {
	ct := &WardenCryptoTokenType{}
	meta := ct.Metadata()

	assert.Equal(t, "warden_crypto_token", meta.Name)
	assert.Equal(t, "wcrt_", meta.IDPrefix)
	assert.Equal(t, "cwc.", meta.ValuePrefix)
	assert.Equal(t, 1*time.Hour, meta.DefaultTTL)
}

func TestCryptoTokenType_Generate(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	authData := &AuthData{
		PrincipalID:    "test-user",
		RoleName:       "test-role",
		ExpireAt:       time.Now().Add(1 * time.Hour),
		Policies:       []string{"default", "admin"},
		ClientIP:       "10.0.0.1",
		CredentialSpec: "my-spec",
	}

	entry, err := core.tokenStore.GenerateToken(ctx, TypeWardenCryptoToken, authData)
	require.NoError(t, err)
	require.NotNil(t, entry)

	assert.Equal(t, TypeWardenCryptoToken, entry.Type)
	assert.True(t, strings.HasPrefix(entry.Data["token"], "cwc."))
	assert.True(t, strings.HasPrefix(entry.ID, "wcrt_"))
	assert.Equal(t, "test-user", entry.PrincipalID)
	assert.Equal(t, "test-role", entry.RoleName)
}

func TestCryptoTokenType_RoundTrip(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	authData := &AuthData{
		PrincipalID:    "roundtrip-user",
		RoleName:       "roundtrip-role",
		ExpireAt:       time.Now().Add(1 * time.Hour),
		Policies:       []string{"policy-a", "policy-b"},
		ClientIP:       "10.0.0.2",
		CredentialSpec: "spec-1",
	}

	entry, err := core.tokenStore.GenerateToken(ctx, TypeWardenCryptoToken, authData)
	require.NoError(t, err)

	// Decrypt and verify claims
	cryptoType := &WardenCryptoTokenType{encryptor: core.barrier}
	claims, err := cryptoType.DecryptToken(ctx, entry.Data["token"])
	require.NoError(t, err)

	assert.Equal(t, "roundtrip-user", claims.PrincipalID)
	assert.Equal(t, "roundtrip-role", claims.RoleName)
	assert.Equal(t, []string{"policy-a", "policy-b"}, claims.Policies)
	assert.Equal(t, "10.0.0.2", claims.CreatedByIP)
	assert.Equal(t, "spec-1", claims.CredentialSpec)
	assert.Equal(t, namespace.RootNamespaceID, claims.NamespaceID)
	assert.NotEmpty(t, claims.Accessor)
	assert.True(t, claims.ExpireAt > 0)
	assert.True(t, claims.CreatedAt > 0)
}

func TestCryptoTokenType_ValidateValue(t *testing.T) {
	ct := &WardenCryptoTokenType{}

	tests := []struct {
		name  string
		value string
		valid bool
	}{
		{"valid prefix", "cwc.dGVzdA", true},
		{"empty payload", "cwc.", false},
		{"wrong prefix", "cws.dGVzdA", false},
		{"no prefix", "dGVzdA", false},
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.valid, ct.ValidateValue(tt.value))
		})
	}
}

func TestCryptoTokenType_ResolveToken(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	authData := &AuthData{
		PrincipalID: "resolve-user",
		RoleName:    "resolve-role",
		ExpireAt:    time.Now().Add(1 * time.Hour),
		Policies:    []string{"default"},
	}

	entry, err := core.tokenStore.GenerateToken(ctx, TypeWardenCryptoToken, authData)
	require.NoError(t, err)

	// ResolveToken should decrypt inline without cache lookup
	principalID, roleName, err := core.tokenStore.ResolveToken(ctx, entry.Data["token"])
	require.NoError(t, err)
	assert.Equal(t, "resolve-user", principalID)
	assert.Equal(t, "resolve-role", roleName)
}

func TestCryptoTokenType_LookupToken(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	authData := &AuthData{
		PrincipalID:    "lookup-user",
		RoleName:       "lookup-role",
		ExpireAt:       time.Now().Add(1 * time.Hour),
		Policies:       []string{"default", "reader"},
		CredentialSpec: "lookup-spec",
	}

	entry, err := core.tokenStore.GenerateToken(ctx, TypeWardenCryptoToken, authData)
	require.NoError(t, err)

	// LookupToken should reconstruct a full TokenEntry from claims
	looked, err := core.LookupToken(ctx, entry.Data["token"])
	require.NoError(t, err)
	require.NotNil(t, looked)

	assert.Equal(t, TypeWardenCryptoToken, looked.Type)
	assert.Equal(t, "lookup-user", looked.PrincipalID)
	assert.Equal(t, "lookup-role", looked.RoleName)
	assert.Equal(t, []string{"default", "reader"}, looked.Policies)
	assert.Equal(t, "lookup-spec", looked.CredentialSpec)
	assert.Equal(t, namespace.RootNamespaceID, looked.NamespaceID)
}

func TestCryptoTokenType_ExpiredToken(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	authData := &AuthData{
		PrincipalID: "expired-user",
		RoleName:    "expired-role",
		ExpireAt:    time.Now().Add(-1 * time.Hour), // already expired
		Policies:    []string{"default"},
	}

	// GenerateToken rejects already-expired tokens
	_, err := core.tokenStore.GenerateToken(ctx, TypeWardenCryptoToken, authData)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "token already expired")
}

func TestCryptoTokenType_NoPersistence(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	authData := &AuthData{
		PrincipalID: "no-persist-user",
		RoleName:    "no-persist-role",
		ExpireAt:    time.Now().Add(1 * time.Hour),
		Policies:    []string{"default"},
	}

	entry, err := core.tokenStore.GenerateToken(ctx, TypeWardenCryptoToken, authData)
	require.NoError(t, err)

	// Clear cache — crypto tokens should NOT be in persistent storage
	core.tokenStore.byID.Clear()
	core.tokenStore.byID.Wait()

	// ResolveToken should still work (decrypts from the token value itself)
	principalID, roleName, err := core.tokenStore.ResolveToken(ctx, entry.Data["token"])
	require.NoError(t, err)
	assert.Equal(t, "no-persist-user", principalID)
	assert.Equal(t, "no-persist-role", roleName)
}

func TestCryptoTokenType_DecryptInvalidToken(t *testing.T) {
	core := createTestCore(t)

	cryptoType := &WardenCryptoTokenType{encryptor: core.barrier}

	_, err := cryptoType.DecryptToken(context.Background(), "cwc.invalidciphertext")
	require.Error(t, err)

	_, err = cryptoType.DecryptToken(context.Background(), "wrong.prefix")
	require.Error(t, err)
}
