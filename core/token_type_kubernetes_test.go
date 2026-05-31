package core

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const sampleK8sSAJWT = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2t1YmVybmV0ZXMuZGVmYXVsdC5zdmMiLCJzdWIiOiJzeXN0ZW06c2VydmljZWFjY291bnQ6ZGVmYXVsdDpteWFwcCJ9.sig"

func TestKubernetesRoleTokenType_Metadata(t *testing.T) {
	kt := &KubernetesRoleTokenType{}
	meta := kt.Metadata()

	assert.Equal(t, "kubernetes_role", meta.Name)
	assert.Equal(t, TypeKubernetesRole, meta.Name, "constant must match metadata name")
	assert.Equal(t, "kubr_", meta.IDPrefix)
	assert.Equal(t, "", meta.ValuePrefix,
		"ValuePrefix MUST be empty - jwt_role owns the eyJ prefix in the registry; "+
			"the kubernetes type reaches the cache via performImplicitAuth's mount-type dispatch, "+
			"not via prefix-based DetectType")
	assert.Equal(t, "kubernetes", meta.AuthMethodType,
		"AuthMethodType wires this TokenType to mounts of type 'kubernetes' via the registry")
}

func TestKubernetesRoleTokenType_ImplementsTransparentTokenType(t *testing.T) {
	// Compile-time assertion lives in token_type_kubernetes.go; this is
	// the runtime equivalent so a test failure surfaces the contract.
	var tt TransparentTokenType = &KubernetesRoleTokenType{}
	assert.True(t, tt.IsTransparent(),
		"KubernetesRoleTokenType must opt into transparent-family behaviors via IsTransparent()")
	assert.Equal(t, "k8s_sa_jwt", tt.CredentialFormat(),
		"CredentialFormat must be 'k8s_sa_jwt' (distinct from generic 'jwt') so the "+
			"introspect aggregator only fans K8s SA tokens out to kubernetes mounts")
}

func TestKubernetesRoleTokenType_ValidateValue(t *testing.T) {
	kt := &KubernetesRoleTokenType{}

	t.Run("valid 3-segment JWT", func(t *testing.T) {
		assert.True(t, kt.ValidateValue(sampleK8sSAJWT))
	})
	t.Run("missing eyJ prefix", func(t *testing.T) {
		assert.False(t, kt.ValidateValue("AAA.BBB.CCC"))
	})
	t.Run("two segments only", func(t *testing.T) {
		assert.False(t, kt.ValidateValue("eyJhdr.eyJsig"))
	})
	t.Run("empty segment", func(t *testing.T) {
		assert.False(t, kt.ValidateValue("eyJ..sig"))
	})
}

func TestKubernetesRoleTokenType_LookupValue_IncludesMountAccessor(t *testing.T) {
	kt := &KubernetesRoleTokenType{}

	// Same JWT + same role, different mount accessors → different hashes.
	// This is the load-bearing property: two kubernetes mounts (e.g. two
	// spokes) with the same workload SA token + same role name must not
	// share a cache entry.
	h1 := kt.LookupValue(sampleK8sSAJWT, "accessor-A", "deploy")
	h2 := kt.LookupValue(sampleK8sSAJWT, "accessor-B", "deploy")
	assert.NotEqual(t, h1, h2,
		"mount accessor must namespace the cache key")
}

func TestKubernetesRoleTokenType_LookupValue_DifferentRolesProduceDifferentHashes(t *testing.T) {
	kt := &KubernetesRoleTokenType{}
	h1 := kt.LookupValue(sampleK8sSAJWT, "acc1", "role1")
	h2 := kt.LookupValue(sampleK8sSAJWT, "acc1", "role2")
	assert.NotEqual(t, h1, h2)
}

func TestKubernetesRoleTokenType_LookupValue_IsDeterministic(t *testing.T) {
	kt := &KubernetesRoleTokenType{}
	h1 := kt.LookupValue(sampleK8sSAJWT, "acc1", "deploy")
	h2 := kt.LookupValue(sampleK8sSAJWT, "acc1", "deploy")
	assert.Equal(t, h1, h2)
}

func TestKubernetesRoleTokenType_LookupValue_HashShapeMatchesProductionExpectation(t *testing.T) {
	// performImplicitAuth (and the singleflight key) build the same
	// (mountAccessor + ":" + credential + ":" + role) shape. Pin the
	// exact format here so the dispatch code and the TokenType stay in
	// agreement; if either side changes the hash input shape without
	// the other, transparent-mode cache lookups silently miss.
	kt := &KubernetesRoleTokenType{}
	expected := sha256.Sum256([]byte("accX:" + sampleK8sSAJWT + ":role-Y"))
	assert.Equal(t, hex.EncodeToString(expected[:]), kt.LookupValue(sampleK8sSAJWT, "accX", "role-Y"))
}

func TestKubernetesRoleTokenType_LookupValue_DoesNotCollideWithJWTRoleTokenType(t *testing.T) {
	// Defense in depth: even with the per-type IDPrefix ("jwtr_" vs
	// "kubr_") making the final cache IDs disjoint, the underlying
	// hash inputs should also differ. Same JWT + accessor + role hashed
	// by two different transparent types must not collide on LookupValue.
	jwtType := &JWTRoleTokenType{}
	k8sType := &KubernetesRoleTokenType{}
	assert.Equal(t, jwtType.LookupValue(sampleK8sSAJWT, "acc", "r"),
		k8sType.LookupValue(sampleK8sSAJWT, "acc", "r"),
		"hash inputs are identical (both shapes are mountAccessor+cred+role); "+
			"separation comes from ComputeID's per-type IDPrefix")

	jwtID := jwtType.ComputeID(jwtType.LookupValue(sampleK8sSAJWT, "acc", "r"))
	k8sID := k8sType.ComputeID(k8sType.LookupValue(sampleK8sSAJWT, "acc", "r"))
	assert.NotEqual(t, jwtID, k8sID,
		"cache IDs must differ across TokenTypes even for identical hash inputs")
	assert.True(t, strings.HasPrefix(jwtID, "jwtr_"))
	assert.True(t, strings.HasPrefix(k8sID, "kubr_"))
}

func TestKubernetesRoleTokenType_Generate_StoresHashedLookupValueUnderJWTKey(t *testing.T) {
	kt := &KubernetesRoleTokenType{}
	entry := &TokenEntry{Data: make(map[string]string)}
	auth := &AuthData{
		TokenValue:    sampleK8sSAJWT,
		MountAccessor: "acc-1",
		RoleName:      "deploy",
	}
	data, err := kt.Generate(context.Background(), auth, entry)
	require.NoError(t, err)

	stored, ok := data[kt.LookupKey()]
	require.True(t, ok, "Generate must populate entry.Data[\"jwt\"]")
	expected := kt.LookupValue(sampleK8sSAJWT, "acc-1", "deploy")
	assert.Equal(t, expected, stored,
		"stored value must match what LookupTransparentTokenWithRole will compute")
}

func TestKubernetesRoleTokenType_Generate_NoOpOnNilOrEmpty(t *testing.T) {
	kt := &KubernetesRoleTokenType{}
	t.Run("nil authData", func(t *testing.T) {
		entry := &TokenEntry{Data: map[string]string{"existing": "preserved"}}
		out, err := kt.Generate(context.Background(), nil, entry)
		require.NoError(t, err)
		_, ok := out[kt.LookupKey()]
		assert.False(t, ok, "should not populate jwt key when authData is nil")
		assert.Equal(t, "preserved", out["existing"])
	})
	t.Run("empty TokenValue", func(t *testing.T) {
		entry := &TokenEntry{Data: make(map[string]string)}
		_, err := kt.Generate(context.Background(), &AuthData{TokenValue: ""}, entry)
		require.NoError(t, err)
	})
}

func TestKubernetesRoleTokenType_RegisteredInBuiltinTypes(t *testing.T) {
	registry := NewTokenTypeRegistry()
	require.NoError(t, registry.Register(&KubernetesRoleTokenType{}))

	// Lookup by name.
	tt, err := registry.GetByName("kubernetes_role")
	require.NoError(t, err)
	assert.Equal(t, "kubernetes_role", tt.Metadata().Name)

	// Lookup by auth-method type (the PR1+PR2 dispatch path).
	tt2 := registry.GetTransparentTokenTypeForAuthMethod("kubernetes")
	require.NotNil(t, tt2, "registry must index kubernetes_role under AuthMethodType=kubernetes")
	assert.Equal(t, "k8s_sa_jwt", tt2.CredentialFormat())

	// IsTransparent reports true so the explicit-login guard and cache-only
	// persistence opt in via the registry.
	assert.True(t, registry.IsTransparent("kubernetes_role"))
}

// TestTokenStore_KubernetesRoleEnrolledInGuard_AndDispatch pins the
// end-to-end registration via a real TokenStore (the path Core uses).
// All three transparent role types must report IsTransparentType=true
// so the explicit-login guard at request_handler.go:638 rejects external
// POST /auth/<mount>/login attempts uniformly. Verifying this through
// the TokenStore (not just the registry directly) catches breakage in
// the registerBuiltinTypes() wiring.
func TestTokenStore_KubernetesRoleEnrolledInGuard_AndDispatch(t *testing.T) {
	core := createTestCore(t)
	require.NotNil(t, core.tokenStore, "test core must have a token store")

	// All transparent types report true.
	for _, name := range []string{"jwt_role", "cert_role", "kubernetes_role"} {
		assert.True(t, core.tokenStore.IsTransparentType(name),
			"%s must be classified as transparent so the explicit-login guard fires", name)
	}
	// Non-transparent type reports false.
	assert.False(t, core.tokenStore.IsTransparentType("warden_token"),
		"warden_token is a persisted bearer token, not transparent")
	// Unknown type reports false.
	assert.False(t, core.tokenStore.IsTransparentType("nonexistent_role"))

	// Mount-type → TransparentTokenType lookup must round-trip for
	// kubernetes mounts (PR2's dispatch depends on this).
	tt := core.tokenStore.GetTransparentTokenTypeForAuthMethod("kubernetes")
	require.NotNil(t, tt, "GetTransparentTokenTypeForAuthMethod(\"kubernetes\") must return KubernetesRoleTokenType")
	assert.Equal(t, "kubernetes_role", tt.Metadata().Name)
	assert.Equal(t, "k8s_sa_jwt", tt.CredentialFormat())
}
