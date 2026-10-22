package jwt

import (
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v3"
	josejwt "github.com/go-jose/go-jose/v3/jwt"
	capjwt "github.com/hashicorp/cap/jwt"
	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/auth/helper"
	"github.com/stephnangue/warden/auth/helper/factstest"
	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/helper/selector"
	"github.com/stephnangue/warden/logical"
)

const factsTestIssuer = "https://issuer.example.com"

// signES256 mints a JWT carrying claims, signed by key.
func signES256(t testing.TB, key *ecdsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: key},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	require.NoError(t, err)
	token, err := josejwt.Signed(signer).Claims(claims).CompactSerialize()
	require.NoError(t, err)
	return token
}

// factsBackend returns a backend with storage, configured with a static key,
// the test issuer and audience "warden", plus extra config keys.
func factsBackend(t *testing.T, extra map[string]any) (*jwtAuthBackend, *ecdsa.PrivateKey) {
	t.Helper()
	privAny, pemStr := genTestPubKeyPEM(t, "ECDSA")
	b, _ := createTestBackendWithStorage(t)
	raw := map[string]any{
		"jwt_validation_pubkeys": []string{pemStr},
		"bound_issuer":           factsTestIssuer,
		"bound_audiences":        []string{"warden"},
	}
	for k, v := range extra {
		raw[k] = v
	}
	resp := writeConfig(b, raw)
	require.Equal(t, http.StatusOK, resp.StatusCode, "config write: %v", resp.Err)
	return b, privAny.(*ecdsa.PrivateKey)
}

// baseClaims are valid claims for factsBackend, merged with extra.
func baseClaims(extra map[string]any) map[string]any {
	now := time.Now()
	c := map[string]any{
		"iss": factsTestIssuer,
		"sub": "agent-1",
		"aud": "warden",
		"iat": now.Unix(),
		"exp": now.Add(time.Hour).Unix(),
	}
	for k, v := range extra {
		c[k] = v
	}
	return c
}

func login(t *testing.T, b *jwtAuthBackend, token string) *logical.Response {
	t.Helper()
	resp, err := b.handleLogin(context.Background(), &logical.Request{}, &framework.FieldData{
		Raw:    map[string]any{"jwt": token},
		Schema: b.pathLogin().Fields,
	})
	require.NoError(t, err)
	return resp
}

// compileFacts compiles kind and facts as a jwt mount config does.
func compileFacts(kind string, facts map[string]string) (*logical.MountNaming, error) {
	fc := helper.FactsConfig{EntityKind: kind, Facts: facts}
	fc.Compile(jwtBuiltinFacts())
	return fc.Naming(), fc.Err()
}

// =============================================================================
// Facts from claims
// =============================================================================

func TestFacts_FromClaims(t *testing.T) {
	naming, err := compileFacts("", map[string]string{
		"repository":      "repo",
		"/deployment/env": "env",
		"/deployment/0":   "first", // an object has no index
		"/stages/1":       "second_stage",
		"groups":          "groups",
		"run_attempt":     "attempt",
		"ratio":           "ratio",
		"admin":           "admin",
		"sub":             "sub",
		"nested":          "nested_obj",
	})
	require.NoError(t, err)

	claims := map[string]any{
		"iss":         factsTestIssuer,
		"sub":         "repo:acme/app:ref:refs/heads/main",
		"aud":         []any{"warden", "other"},
		"repository":  "acme/app",
		"deployment":  map[string]any{"env": "prod"},
		"stages":      []any{"build", "deploy"},
		"groups":      []any{"g1", map[string]any{"x": 1.0}, "g2", 3.0, true},
		"run_attempt": 2.0,
		"ratio":       1.5,
		"admin":       true,
		"nested":      map[string]any{"a": "b"},
		"secret":      "unmapped",
	}
	adm := newAdmission(claims, "", nil)

	cases := []struct {
		name string
		want []string
	}{
		{"sub", []string{"repo:acme/app:ref:refs/heads/main"}},
		{"iss", []string{factsTestIssuer}},
		{"aud", []string{"warden", "other"}},
		{"repo", []string{"acme/app"}},
		{"env", []string{"prod"}},
		{"first", nil},
		{"second_stage", []string{"deploy"}},
		{"groups", []string{"g1", "g2", "3", "true"}}, // objects skipped
		{"attempt", []string{"2"}},
		{"ratio", []string{"1.5"}},
		{"admin", []string{"true"}},
		{"nested_obj", nil}, // an object is not a value
		{"secret", nil},     // invisible until mapped
		{"deployment", nil}, // the raw name of a mapped source is not a name
		{"repository", nil},
		{"kind", []string{logical.EntityKindAgent}},
		{"mount", nil}, // set by core at LoginCreateToken
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, factstest.Values(adm, naming, tc.name), "fact %q", tc.name)
	}

	assert.Equal(t, map[string]string{
		"repo":         "acme/app",
		"env":          "prod",
		"second_stage": "deploy",
		"groups":       "g1,g2,3,true",
		"attempt":      "2",
		"ratio":        "1.5",
		"admin":        "true",
		"sub":          "repo:acme/app:ref:refs/heads/main",
	}, adm.RenderMetadata(naming))
}

// Claims decoded with UseNumber hold json.Number, which is a fact and an iat;
// a Go integer is neither a JSON-decoded value nor a fact (selector.NewClaims),
// though it is still read as an iat.
func TestFacts_NumberTypes(t *testing.T) {
	naming, err := compileFacts("", map[string]string{"attempt": "attempt", "count": "count"})
	require.NoError(t, err)
	claims := map[string]any{
		"attempt": json.Number("2"),
		"count":   int64(7),
		"iat":     json.Number("1700000000"),
	}
	adm := newAdmission(claims, "", nil)
	assert.Equal(t, []string{"2"}, factstest.Values(adm, naming, "attempt"))
	assert.Empty(t, factstest.Values(adm, naming, "count"))
	assert.Equal(t, map[string]string{"attempt": "2"}, adm.RenderMetadata(naming))
	assert.Equal(t, time.Unix(1700000000, 0), adm.IssuedAt)

	adm = newAdmission(map[string]any{"iat": int64(1700000000)}, "", nil)
	assert.Equal(t, time.Unix(1700000000, 0), adm.IssuedAt)
}

// FactsConfig is flattened into the config's own keys on the way in (the
// map round-trip in mapToJWTAuthConfig) and on the way to storage.
func TestFactsConfig_JSONFlattened(t *testing.T) {
	config, err := mapToJWTAuthConfig(map[string]any{
		"jwks_url":    "https://example.com/jwks",
		"entity_kind": "human",
		"facts":       map[string]any{"repository": "repo"},
	})
	require.NoError(t, err)
	assert.Equal(t, "human", config.EntityKind)
	assert.Equal(t, map[string]string{"repository": "repo"}, config.Facts)

	raw, err := json.Marshal(config)
	require.NoError(t, err)
	var flat map[string]any
	require.NoError(t, json.Unmarshal(raw, &flat))
	assert.Equal(t, "human", flat["entity_kind"])
	assert.Equal(t, map[string]any{"repository": "repo"}, flat["facts"])
	assert.NotContains(t, flat, "FactsConfig")
}

func TestFactNames(t *testing.T) {
	b, _ := factsBackend(t, nil)
	assert.Equal(t, []string{"aud", "iss", "sub"}, b.FactNames())

	require.Equal(t, http.StatusOK, writeConfig(b, map[string]any{
		"facts": map[string]any{"repository": "repo", "/deployment/env": "env"},
	}).StatusCode)
	names := b.FactNames()
	assert.Equal(t, []string{"aud", "env", "iss", "repo", "sub"}, names)

	// The result is the caller's: changing it leaves the mount's alone.
	names[0] = "changed"
	assert.Equal(t, "aud", b.FactNames()[0])

	unconfigured, _ := createTestBackendWithStorage(t)
	assert.Empty(t, unconfigured.FactNames())
}

// =============================================================================
// Login is an admission
// =============================================================================

func TestLogin_CarriesAdmission(t *testing.T) {
	b, key := factsBackend(t, map[string]any{
		"facts": map[string]any{"/deployment/env": "env"},
	})
	claims := baseClaims(map[string]any{
		"deployment": map[string]any{"env": "prod"},
		"act":        map[string]any{"sub": "broker"},
	})
	token := signES256(t, key, claims)

	resp := login(t, b, token)
	require.Equal(t, http.StatusOK, resp.StatusCode, "login: %v", resp.Err)
	auth := resp.Auth
	require.NotNil(t, auth)

	// An admission: no policies, no metadata, no role or spec to carry.
	assert.Nil(t, auth.Policies)
	assert.Nil(t, auth.Metadata)
	assert.Equal(t, "jwt_role", auth.TokenType)
	assert.Equal(t, token, auth.ClientToken)
	assert.Equal(t, "agent-1", auth.PrincipalID)
	assert.InDelta(t, time.Hour.Seconds(), auth.TokenTTL.Seconds(), 5, "min(token_ttl, exp)")
	assert.NotContains(t, resp.Data, "role")
	require.Len(t, auth.Actors, 1)
	assert.Equal(t, "broker", auth.Actors[0].Subject)

	adm := auth.Admission
	require.NotNil(t, adm)
	assert.Same(t, b.mountFacts, adm.Mount, "the admission shares the mount's live naming")
	assert.Empty(t, adm.MountPath, "core names the mount")
	assert.Equal(t, time.Unix(claims["iat"].(int64), 0), adm.IssuedAt)
	payload := strings.Split(token, ".")[1]
	assert.Equal(t, int64(base64.RawURLEncoding.DecodedLen(len(payload))), adm.Bytes)
	assert.Positive(t, adm.Size())

	n := adm.Mount.Load()
	assert.Equal(t, []string{"agent-1"}, factstest.Values(adm, n, "sub"))
	assert.Equal(t, []string{"warden"}, factstest.Values(adm, n, "aud"))
	assert.Equal(t, []string{"prod"}, factstest.Values(adm, n, "env"))
	assert.Empty(t, factstest.Values(adm, n, "act"))
}

// A failed login carries no admission.
func TestLogin_RefusedCarriesNoAdmission(t *testing.T) {
	b, key := factsBackend(t, nil)
	token := signES256(t, key, baseClaims(map[string]any{"aud": "someone-else"}))
	resp := login(t, b, token)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Nil(t, resp.Auth)
}

// An Entra-like token with 200 groups is admitted whole; its groups are a fact
// only once the mount maps them, and a mapping edit reaches the admission
// already issued.
func TestLogin_EntraLikeTokenWithManyGroups(t *testing.T) {
	b, key := factsBackend(t, nil)
	groups := make([]any, 200)
	for i := range groups {
		groups[i] = fmt.Sprintf("%08x-1d2c-4e5f-8a9b-%012x", i, i*7919)
	}
	token := signES256(t, key, baseClaims(map[string]any{
		"tid":    "72f988bf-86f1-41af-91ab-2d7cd011db47",
		"oid":    "4a1b2c3d-0000-4e5f-8a9b-0123456789ab",
		"roles":  []any{"Reader", "Deployer"},
		"wids":   []any{"b79fbf4d-3ef9-4689-8143-76b194e85509"},
		"groups": groups,
	}))
	assert.Greater(t, len(token), 8000)

	resp := login(t, b, token)
	require.Equal(t, http.StatusOK, resp.StatusCode, "login: %v", resp.Err)
	adm := resp.Auth.Admission
	require.NotNil(t, adm)
	assert.Greater(t, adm.Bytes, int64(8000))

	assert.Empty(t, factstest.Values(adm, adm.Mount.Load(), "groups"), "groups are invisible until mapped")

	require.Equal(t, http.StatusOK, writeConfig(b, map[string]any{
		"facts": map[string]any{"groups": "groups"},
	}).StatusCode)
	got := factstest.Values(adm, adm.Mount.Load(), "groups")
	require.Len(t, got, 200)
	assert.Equal(t, groups[199], got[199])
}

// =============================================================================
// Metadata equivalence: the mapping renders what metadata_claims extracts
// =============================================================================

func TestRenderMetadata_EquivalentToExtractMetadata(t *testing.T) {
	cases := []struct {
		name    string
		claims  map[string]any
		mapping map[string]string
	}{
		{"top-level and nested", map[string]any{
			"team":            "platform-core",
			"resource_access": map[string]any{"warden": map[string]any{"env": "prod"}},
		}, map[string]string{"team": "team", "/resource_access/warden/env": "env"}},
		{"no mappings", map[string]any{"team": "x"}, nil},
		{"absent claim skipped", map[string]any{"team": "platform"},
			map[string]string{"team": "team", "env": "env"}},
		{"all absent", map[string]any{}, map[string]string{"env": "env"}},
		{"act.sub consent binding", map[string]any{
			"sub": "user-8f21c3", "team": "platform",
			"act": map[string]any{"sub": "agent-gateway"},
		}, map[string]string{"/act/sub": "acting_agent", "team": "team"}},
		{"outermost actor of a chain", map[string]any{
			"sub": "user-8f21c3",
			"act": map[string]any{
				"sub": "broker-beta",
				"act": map[string]any{"sub": "agent-gateway"},
			},
		}, map[string]string{"/act/sub": "acting_agent", "team": "team"}},
		{"absent act", map[string]any{"sub": "user-8f21c3", "team": "platform"},
			map[string]string{"/act/sub": "acting_agent", "team": "team"}},
		{"namespaced claim key", map[string]any{"https://warden.io/env": "staging"},
			map[string]string{"https://warden.io/env": "env"}},
		{"array index pointer", map[string]any{"stages": []any{"build", "deploy"}},
			map[string]string{"/stages/1": "stage"}},
		{"empty string", map[string]any{"team": ""}, map[string]string{"team": "team"}},
		{"renamed built-in source", map[string]any{"sub": "agent-1"},
			map[string]string{"sub": "sub", "iss": "issuer"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			want, err := extractMetadata(tc.claims, tc.mapping)
			require.NoError(t, err)
			naming, err := compileFacts("", tc.mapping)
			require.NoError(t, err)
			adm := newAdmission(tc.claims, "", nil)
			assert.Equal(t, want, adm.RenderMetadata(naming))
		})
	}
}

// The one documented difference: a non-string claim fails the login today and
// renders under the mapping (an object, which is no value, is left out).
func TestRenderMetadata_NonStringClaimRenders(t *testing.T) {
	cases := []struct {
		name   string
		claims map[string]any
		source string
		want   map[string]string
	}{
		{"list", map[string]any{"roles": []any{"a", "b"}}, "roles", map[string]string{"x": "a,b"}},
		{"number", map[string]any{"level": 42.0}, "level", map[string]string{"x": "42"}},
		{"bool", map[string]any{"admin": true}, "admin", map[string]string{"x": "true"}},
		{"malformed act.sub", map[string]any{"act": map[string]any{"sub": 42.0}}, "/act/sub", map[string]string{"x": "42"}},
		{"object", map[string]any{"act": map[string]any{"sub": "a"}}, "act", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mapping := map[string]string{tc.source: "x"}
			_, err := extractMetadata(tc.claims, mapping)
			require.Error(t, err, "today's extractor refuses a non-string claim")
			naming, err := compileFacts("", mapping)
			require.NoError(t, err)
			assert.Equal(t, tc.want, newAdmission(tc.claims, "", nil).RenderMetadata(naming))
		})
	}
}

// =============================================================================
// Config: entity_kind and facts
// =============================================================================

func TestConfigWrite_Facts(t *testing.T) {
	b, _ := factsBackend(t, nil)
	ctx := context.Background()

	read := func() map[string]any {
		resp, err := b.handleConfigRead(ctx, &logical.Request{}, &framework.FieldData{})
		require.NoError(t, err)
		return resp.Data
	}
	assert.Equal(t, logical.EntityKindAgent, read()["entity_kind"], "agent by default")
	assert.Empty(t, read()["facts"])

	require.Equal(t, http.StatusOK, writeConfig(b, map[string]any{
		"entity_kind": "human",
		"facts":       map[string]any{"repository": "repo", "/deployment/env": "env"},
	}).StatusCode)
	data := read()
	assert.Equal(t, "human", data["entity_kind"])
	assert.Equal(t, map[string]string{"repository": "repo", "/deployment/env": "env"}, data["facts"])
	n := b.mountFacts.Load()
	require.NotNil(t, n)
	assert.Equal(t, "human", n.Kind)
	assert.Equal(t, []string{"env", "repo"}, n.Mapping.Mapped())

	// A write that leaves facts out keeps them.
	require.Equal(t, http.StatusOK, writeConfig(b, map[string]any{"bound_subject": "x"}).StatusCode)
	assert.Equal(t, []string{"env", "repo"}, b.mountFacts.Load().Mapping.Mapped())
	assert.Equal(t, "human", b.mountFacts.Load().Kind)

	// The stored config reloads into the same naming.
	entry, err := b.storageView.Get(ctx, "config")
	require.NoError(t, err)
	var stored map[string]any
	require.NoError(t, entry.DecodeJSON(&stored))
	assert.Equal(t, "human", stored["entity_kind"])
	assert.Equal(t, map[string]any{"repository": "repo", "/deployment/env": "env"}, stored["facts"])
	reloaded, _ := createTestBackendWithStorage(t)
	reloaded.storageView = b.storageView
	require.NoError(t, reloaded.Initialize(ctx))
	assert.Equal(t, b.mountFacts.Load().Kind, reloaded.mountFacts.Load().Kind)
	assert.Equal(t, b.mountFacts.Load().Mapping.Names(), reloaded.mountFacts.Load().Mapping.Names())

	// An empty map clears the mapping.
	require.Equal(t, http.StatusOK, writeConfig(b, map[string]any{"facts": map[string]any{}}).StatusCode)
	assert.Empty(t, b.mountFacts.Load().Mapping.Mapped())
	assert.Equal(t, []string{"aud", "iss", "sub"}, b.FactNames())
}

// The config read hands out copies: changing one leaves the live config alone.
// The facts field says what a jwt source is.
func TestConfigRead_Copies(t *testing.T) {
	b, _ := factsBackend(t, map[string]any{"facts": map[string]any{"team": "team"}})
	resp, err := b.handleConfigRead(context.Background(), &logical.Request{}, &framework.FieldData{})
	require.NoError(t, err)
	resp.Data["bound_audiences"].([]string)[0] = "changed"
	resp.Data["jwt_validation_pubkeys"].([]string)[0] = "changed"
	resp.Data["facts"].(map[string]string)["team"] = "changed"
	assert.Equal(t, []string{"warden"}, b.config.BoundAudiences)
	assert.NotEqual(t, "changed", b.config.JWTValidationPubKeys[0])
	assert.Equal(t, map[string]string{"team": "team"}, b.config.Facts)

	assert.Contains(t, b.pathConfig().Fields["facts"].Description, "a claim name, or a JSON Pointer")
}

func TestConfigWrite_FactsRefused(t *testing.T) {
	cases := []struct {
		name string
		raw  map[string]any
		want string
	}{
		{"bad name", map[string]any{"facts": map[string]any{"team": "Team"}}, "facts:"},
		{"reserved mount", map[string]any{"facts": map[string]any{"path": "mount"}}, "reserved"},
		{"reserved kind", map[string]any{"facts": map[string]any{"type": "kind"}}, "reserved"},
		{"two sources one name", map[string]any{"facts": map[string]any{"username": "workload", "/k8s/uid": "workload"}},
			`fact "workload" is produced by both`},
		{"another source onto a built-in", map[string]any{"facts": map[string]any{"email": "sub"}}, "built-in"},
		{"bad pointer", map[string]any{"facts": map[string]any{"/a~2": "a"}}, "facts:"},
		{"non-string name", map[string]any{"facts": map[string]any{"team": 5}}, "must be a string"},
		{"unknown entity_kind", map[string]any{"entity_kind": "robot"}, "entity_kind:"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, _ := factsBackend(t, map[string]any{"facts": map[string]any{"team": "team"}})
			beforeConfig := b.config
			beforeNaming := b.mountFacts.Load()
			beforeEntry, err := b.storageView.Get(context.Background(), "config")
			require.NoError(t, err)

			resp := writeConfig(b, tc.raw)
			require.Equal(t, http.StatusBadRequest, resp.StatusCode)
			require.Error(t, resp.Err)
			assert.Contains(t, resp.Err.Error(), tc.want)

			assert.Same(t, beforeConfig, b.config, "a refused write is not installed")
			assert.Same(t, beforeNaming, b.mountFacts.Load(), "a refused write is not published")
			afterEntry, err := b.storageView.Get(context.Background(), "config")
			require.NoError(t, err)
			assert.Equal(t, beforeEntry.Value, afterEntry.Value, "a refused write is not stored")
		})
	}
}

// A stored config whose facts no longer compile (written under looser rules,
// or edited in storage) does not fail the mount: it is installed with no
// naming, so the mount answers no fact and nothing reading facts can match its
// admissions. Today's role logins are not affected by facts.
func TestNaming_LoadFailureAnswersNoFacts(t *testing.T) {
	ctx := context.Background()
	privAny, pemStr := genTestPubKeyPEM(t, "ECDSA")
	key := privAny.(*ecdsa.PrivateKey)
	bad := map[string]any{
		"jwt_validation_pubkeys": []string{pemStr},
		"bound_issuer":           factsTestIssuer,
		"bound_audiences":        []string{"warden"},
		"facts":                  map[string]any{"path": "mount"},
	}

	t.Run("from storage", func(t *testing.T) {
		b, _ := createTestBackendWithStorage(t)
		entry, err := sdklogical.StorageEntryJSON("config", bad)
		require.NoError(t, err)
		require.NoError(t, b.storageView.Put(ctx, entry))
		require.NoError(t, b.setRole(ctx, &JWTRole{Name: "reader", TokenPolicies: []string{"read"}, TokenTTL: "1h"}))

		require.NoError(t, b.Initialize(ctx), "a bad mapping does not fail the load")
		require.NotNil(t, b.config)
		require.Error(t, b.config.FactsConfig.Err())
		assert.Nil(t, b.mountFacts.Load())
		assert.Empty(t, b.FactNames())

		resp := login(t, b, signES256(t, key, baseClaims(nil)))
		require.Equal(t, http.StatusOK, resp.StatusCode, "role logins do not read facts")
		adm := resp.Auth.Admission
		require.NotNil(t, adm)
		adm.MountPath = "auth/jwt/"
		for _, name := range []string{"sub", "iss", "aud", "mount", "kind"} {
			assert.Empty(t, factstest.Values(adm, adm.Mount.Load(), name), "fact %q", name)
		}

		// A write that leaves the stored facts in place is told how to
		// replace them, and changes nothing.
		before := b.config
		resp = writeConfig(b, map[string]any{"bound_subject": "agent-1"})
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
		assert.EqualError(t, resp.Err, `the stored facts do not compile (facts: fact source "path": "mount" is reserved for every mount and cannot be mapped); send facts (and entity_kind) in this write to replace them`)
		assert.Same(t, before, b.config)

		// Rewriting the facts restores the naming, for this admission too.
		require.Equal(t, http.StatusOK, writeConfig(b, map[string]any{"facts": map[string]any{}}).StatusCode)
		assert.Equal(t, []string{"agent-1"}, factstest.Values(adm, adm.Mount.Load(), "sub"))
	})

	t.Run("from the mount table", func(t *testing.T) {
		backend, err := Factory(ctx, &logical.BackendConfig{Logger: testLogger(), Config: bad})
		require.NoError(t, err, "a bad mapping does not fail the mount")
		b := backend.(*jwtAuthBackend)
		require.Error(t, b.config.FactsConfig.Err())
		assert.Nil(t, b.mountFacts.Load())
	})
}

// The naming is published with the config it was compiled from, in one
// critical section: a reader holding configMu sees them agree, a lock-free
// reader sees one published naming whole, and logins racing config writes
// all share the mount's MountFacts.
func TestNaming_PublishNeverHalfApplied(t *testing.T) {
	b, key := factsBackend(t, nil)
	token := signES256(t, key, baseClaims(map[string]any{"team": "core", "dept": "eng"}))
	writes := []map[string]any{
		{"entity_kind": "agent", "facts": map[string]any{"team": "team"}},
		{"entity_kind": "human", "facts": map[string]any{"dept": "dept", "/x/y": "env"}},
	}
	whole := func(n *logical.MountNaming) bool {
		switch n.Kind {
		case logical.EntityKindAgent:
			return slices.Equal(n.Mapping.Mapped(), []string{"team"})
		case logical.EntityKindHuman:
			return slices.Equal(n.Mapping.Mapped(), []string{"dept", "env"})
		}
		return false
	}
	require.Equal(t, http.StatusOK, writeConfig(b, writes[0]).StatusCode)

	var stop atomic.Bool
	var wg sync.WaitGroup
	errs := make(chan string, 64)
	report := func(format string, args ...any) {
		select {
		case errs <- fmt.Sprintf(format, args...):
		default:
		}
	}

	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() {
				n := b.mountFacts.Load()
				if n == nil || !whole(n) {
					report("lock-free reader saw a partial naming: %+v", n)
				}
				names := b.FactNames()
				if len(names) != 4 && len(names) != 5 {
					report("FactNames saw %v", names)
				}
				b.configMu.RLock()
				if b.config.Naming() != b.mountFacts.Load() {
					report("config and published naming disagree under configMu")
				}
				if b.config.EntityKind != b.config.Naming().Kind {
					report("config entity_kind %q, naming kind %q", b.config.EntityKind, b.config.Naming().Kind)
				}
				b.configMu.RUnlock()
			}
		}()
	}
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() {
				resp := login(t, b, token)
				if resp.StatusCode != http.StatusOK || resp.Auth == nil || resp.Auth.Admission == nil {
					report("login failed: %d %v", resp.StatusCode, resp.Err)
					continue
				}
				adm := resp.Auth.Admission
				if adm.Mount != b.mountFacts {
					report("admission does not share the mount's naming")
				}
				n := adm.Mount.Load()
				if !whole(n) {
					report("admission saw a partial naming")
				}
				// A naming answers what it maps, whichever is in force.
				if n.Kind == logical.EntityKindAgent && len(factstest.Values(adm, n, "team")) != 1 {
					report("agent naming lost team")
				}
			}
		}()
	}

	for i := 0; i < 200; i++ {
		resp := writeConfig(b, writes[i%2])
		require.Equal(t, http.StatusOK, resp.StatusCode)
	}
	stop.Store(true)
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
}

// =============================================================================
// Equivalence: today's role matcher and the role converted to a selector rule
// =============================================================================

// escapeValue writes s as an exact selector value.
func escapeValue(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r == '*' || r == '?' || r == '\\' {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// renderValue writes a bound_claims value as a selector value.
func renderValue(v any) string {
	switch v := v.(type) {
	case string:
		return escapeValue(v)
	case float64:
		return string(selector.FormatScalar(nil, selector.Scalar{Kind: selector.KindNumber, N: v}))
	case bool:
		return string(selector.FormatScalar(nil, selector.Scalar{Kind: selector.KindBool, B: v}))
	}
	panic(fmt.Sprintf("unexpected bound claim %T", v))
}

// convertRole converts one role on a mount to a selector rule: bound claims
// become identity-mapped facts and rule values, bound_subject a "sub" value,
// role audiences an "aud" rule (the mount enforces the union), and the rule
// pins the mount.
//
// A role bound claim on a built-in name (sub, iss, aud) is refused rather than
// converted: it would share the rule's one entry for that name with
// bound_subject or the audiences, and a rule ANDs names but ORs the values of
// one name, so the two constraints cannot both be written there. The
// generator below never binds a built-in claim.
func convertRole(t *testing.T, mountPath string, role *JWTRole) (*selector.Rule, *logical.MountNaming) {
	t.Helper()
	rule := map[string][]string{"mount": {mountPath}}
	facts := map[string]string{}
	if role.BoundSubject != "" {
		rule["sub"] = []string{escapeValue(role.BoundSubject)}
	}
	if len(role.BoundAudiences) > 0 {
		for _, a := range role.BoundAudiences {
			rule["aud"] = append(rule["aud"], escapeValue(a))
		}
	}
	for k, v := range role.BoundClaims {
		if slices.Contains(jwtBuiltinFacts(), k) {
			t.Fatalf("bound claim %q names a built-in fact; it has no single-rule conversion", k)
		}
		facts[k] = k
		rule[k] = []string{renderValue(v)}
	}
	compiled, err := selector.Compile(rule)
	require.NoError(t, err)
	naming, err := compileFacts("", facts)
	require.NoError(t, err)
	return compiled, naming
}

func union(a, b []string) []string {
	out := slices.Concat(a, b)
	slices.Sort(out)
	return slices.Compact(out)
}

// TestEquivalence_RoleMatcherAndConvertedRule checks, over generated claim
// sets, roles and mount configs, that today's matcher (the role's validator
// expectations via validateJWTForRole, then matchRole's config and role bound
// claims) accepts a token exactly when the converted model does: the mount
// validates the issuer, its own bound_subject and the union of the audiences,
// keeps checking its own bound_claims, and the converted rule matches the
// token's admission.
//
// The domain is the one where the conversion is exact: values are scalar,
// same-typed per claim and never empty (a selector value cannot be); role
// bound claims never name a built-in (see convertRole); and a config-level
// bound_subject appears only on samples whose role sets none, since a role's
// subject overrides the mount's today, and a mount that keeps its subject
// cannot express that override.
func TestEquivalence_RoleMatcherAndConvertedRule(t *testing.T) {
	ctx := context.Background()
	b, key := factsBackend(t, nil)
	base := *b.config
	const mountPath = "auth/jwt/"
	mount := &logical.MountFacts{}

	rng := rand.New(rand.NewSource(20261020))
	pick := func(pool []string) string { return pool[rng.Intn(len(pool))] }
	// Each pool holds values a wildcard would widen to, so a missed escape shows.
	subjects := []string{"alice", "bob", "ci*bot", "ci-bot", "a?b", "axb", `back\slash`}
	audiences := []string{"warden", "api", "other*", "otherwise"}
	someAudiences := func() []string {
		if rng.Intn(2) == 0 {
			return nil
		}
		out := []string{pick(audiences)}
		if rng.Intn(2) == 0 {
			out = append(out, pick(audiences))
		}
		return out
	}
	typed := map[string]func() any{
		"team":  func() any { return pick([]string{"core", "edge", "pl*t", "plant", "a?c", "abc"}) },
		"env":   func() any { return pick([]string{"prod", "dev"}) },
		"level": func() any { return []float64{0, 1, 2, 1.5}[rng.Intn(4)] },
		"admin": func() any { return rng.Intn(2) == 0 },
	}
	// Fixed order, so the seed reproduces a run; no built-in name (sub, iss, aud).
	claimNames := []string{"admin", "env", "level", "team"}
	var configSubjects, configClaims int

	var accepted, refused int
	for i := 0; i < 600; i++ {
		claims := baseClaims(nil)
		delete(claims, "aud")
		delete(claims, "sub")
		if rng.Intn(10) > 0 {
			claims["sub"] = pick(subjects)
		}
		switch rng.Intn(3) {
		case 1:
			claims["aud"] = pick(audiences)
		case 2:
			claims["aud"] = []string{pick(audiences), pick(audiences)}
		}
		for _, k := range claimNames {
			gen := typed[k]
			if rng.Intn(10) < 7 {
				claims[k] = gen()
			}
		}

		role := &JWTRole{Name: "r", BoundAudiences: someAudiences(), BoundClaims: map[string]any{}}
		if rng.Intn(2) == 0 {
			role.BoundSubject = pick(subjects)
		}
		for _, k := range claimNames {
			gen := typed[k]
			if rng.Intn(3) == 0 {
				role.BoundClaims[k] = gen()
			}
		}
		cfg := base
		cfg.BoundAudiences = someAudiences()
		cfg.BoundSubject = ""
		cfg.BoundClaims = nil
		if role.BoundSubject == "" && rng.Intn(3) == 0 {
			cfg.BoundSubject = pick(subjects)
			configSubjects++
		}
		if rng.Intn(3) == 0 {
			cfg.BoundClaims = map[string]any{}
			for _, k := range claimNames {
				if rng.Intn(3) == 0 {
					cfg.BoundClaims[k] = typed[k]()
				}
			}
			configClaims++
		}

		token := signES256(t, key, claims)

		// Today: the role's expectations, then the config and role bound
		// claims.
		oldClaims, err := validateJWTForRole(ctx, &cfg, role, token)
		old := err == nil && matchRole(oldClaims, cfg.BoundClaims, role) == nil

		// Converted: the mount validates the issuer, its subject and the
		// audience union and checks its bound claims, all carried unchanged;
		// then the rule matches the admission.
		rule, naming := convertRole(t, mountPath, role)
		got := false
		newClaims, err := cfg.validator.Validate(ctx, token, capjwt.Expected{
			SigningAlgorithms: []capjwt.Alg{capjwt.ES256},
			Issuer:            cfg.BoundIssuer,
			Subject:           cfg.BoundSubject,
			Audiences:         union(cfg.BoundAudiences, role.BoundAudiences),
		})
		if err == nil && validateBoundClaims(newClaims, cfg.BoundClaims) == nil {
			adm := newAdmission(newClaims, token, mount)
			adm.MountPath = mountPath
			got = rule.Match(factstest.Source{Adm: adm, Naming: naming})
		}

		require.Equal(t, old, got, "sample %d: claims %v, role %+v, config subject %q, claims %v, audiences %v",
			i, claims, role, cfg.BoundSubject, cfg.BoundClaims, cfg.BoundAudiences)
		if old {
			accepted++
		} else {
			refused++
		}
	}
	// Both outcomes are exercised, so agreement is not vacuous.
	assert.Greater(t, accepted, 30)
	assert.Greater(t, refused, 30)
	assert.Greater(t, configSubjects, 30)
	assert.Greater(t, configClaims, 30)
}

// The documented widenings: the converted rule accepts where today's
// bound_claims check refuses.
func TestEquivalence_DocumentedWidenings(t *testing.T) {
	cases := []struct {
		name   string
		claims map[string]any
		bound  map[string]any
		rule   map[string][]string
	}{
		{"list-valued claim matches element-wise",
			map[string]any{"groups": []any{"a", "b"}},
			map[string]any{"groups": "a"},
			map[string][]string{"groups": {"a"}}},
		{"list bound value matches any element",
			map[string]any{"groups": "b"},
			map[string]any{"groups": []any{"a", "b"}},
			map[string][]string{"groups": {"a", "b"}}},
		{"string bound value matches a number",
			map[string]any{"level": 1.0},
			map[string]any{"level": "1"},
			map[string][]string{"level": {"1"}}},
		{"number bound value matches a string",
			map[string]any{"level": "1"},
			map[string]any{"level": 1.0},
			map[string][]string{"level": {renderValue(1.0)}}},
		{"bool bound value matches a string",
			map[string]any{"admin": "true"},
			map[string]any{"admin": true},
			map[string][]string{"admin": {renderValue(true)}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Error(t, validateBoundClaims(tc.claims, tc.bound), "today's check refuses")

			facts := map[string]string{}
			for k := range tc.rule {
				facts[k] = k
			}
			naming, err := compileFacts("", facts)
			require.NoError(t, err)
			rule, err := selector.Compile(tc.rule)
			require.NoError(t, err)
			adm := newAdmission(tc.claims, "", nil)
			assert.True(t, rule.Match(factstest.Source{Adm: adm, Naming: naming}), "the converted rule accepts")
		})
	}
}
