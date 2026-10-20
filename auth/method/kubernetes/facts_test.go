package kubernetes

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/auth/helper"
	"github.com/stephnangue/warden/auth/helper/factstest"
	"github.com/stephnangue/warden/framework"
	jwtparse "github.com/stephnangue/warden/helper"
	"github.com/stephnangue/warden/helper/selector"
	"github.com/stephnangue/warden/logical"
)

// apiServerAudience is the audience the test API server validates a token
// against when a TokenReview names none, as a kube-apiserver does with its own
// --api-audiences.
const apiServerAudience = "https://kubernetes.default.svc"

// newReviewingAPIServer starts an API server that answers each TokenReview from
// the reviewed token's own claims, as a kube-apiserver does for tokens it
// signed: sub is the username, uid the uid, and the token is authenticated when
// its aud claim shares an audience with spec.audiences (or with
// apiServerAudience when the review names none); status.audiences is that
// intersection, and the groups are the ones the API server adds for a service
// account. It keeps no state, so concurrent reviews are safe.
func newReviewingAPIServer(t testing.TB) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req tokenReviewRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var status tokenReviewStatus
		claims, err := jwtparse.ParseJWTClaimsUnverified(req.Spec.Token)
		if err != nil {
			status.Error = "invalid token"
		} else {
			want := req.Spec.Audiences
			if len(want) == 0 {
				want = []string{apiServerAudience}
			}
			var both []string
			for _, a := range audienceClaim(claims["aud"]) {
				if slices.Contains(want, a) && !slices.Contains(both, a) {
					both = append(both, a)
				}
			}
			sub, _ := claims["sub"].(string)
			ns, _, ok := parseSAUsername(sub)
			switch {
			case len(both) == 0:
				status.Error = "token audiences are invalid for the target audiences"
			case !ok:
				status.Error = "not a service account token"
			default:
				uid, _ := claims["uid"].(string)
				status = tokenReviewStatus{
					Authenticated: true,
					User: tokenReviewUser{
						Username: sub,
						UID:      uid,
						Groups:   []string{"system:serviceaccounts", "system:serviceaccounts:" + ns, "system:authenticated"},
					},
					Audiences: both,
				}
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(tokenReviewResponse{Status: status})
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// audienceClaim reads a JSON-decoded aud claim: a string or a list of strings.
func audienceClaim(v any) []string {
	switch v := v.(type) {
	case string:
		return []string{v}
	case []any:
		out := make([]string, 0, len(v))
		for _, e := range v {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// saToken mints a service-account token for namespace/name carrying audiences
// and extra claims.
func saToken(namespace, name string, audiences []string, extra map[string]any) string {
	claims := map[string]any{
		"iss": "https://kubernetes.default.svc.cluster.local",
		"sub": serviceAccountUsernamePrefix + namespace + ":" + name,
		"uid": "uid-" + name,
		"aud": audiences,
	}
	for k, v := range extra {
		claims[k] = v
	}
	return mintJWT(claims)
}

// reviewingBackend returns a backend with storage, configured against a
// reviewing API server plus extra config keys, and a role "reader" bound to
// default/myapp that only grants a policy.
func reviewingBackend(t *testing.T, extra map[string]any) *kubernetesAuthBackend {
	t.Helper()
	b, ctx := newTestBackend(t)
	raw := map[string]any{"kubernetes_host": newReviewingAPIServer(t), "tls_skip_verify": true}
	for k, v := range extra {
		raw[k] = v
	}
	resp := writeConfig(b, raw)
	require.Equal(t, http.StatusOK, resp.StatusCode, "config write: %v", resp.Err)
	require.NoError(t, b.setRole(ctx, &KubernetesRole{
		Name:                          "reader",
		BoundServiceAccountNames:      []string{"myapp"},
		BoundServiceAccountNamespaces: []string{"default"},
		TokenPolicies:                 []string{"read"},
		TokenTTL:                      "1h",
		TokenType:                     "kubernetes_role",
	}))
	return b
}

func login(t testing.TB, b *kubernetesAuthBackend, token, role string) *logical.Response {
	t.Helper()
	resp, err := b.handleLogin(context.Background(), &logical.Request{}, &framework.FieldData{
		Raw:    map[string]any{"jwt": token, "role": role},
		Schema: b.pathLogin().Fields,
	})
	require.NoError(t, err)
	return resp
}

// compileFacts compiles kind and facts as a kubernetes mount config does.
func compileFacts(kind string, facts map[string]string) (*logical.MountNaming, error) {
	fc := helper.FactsConfig{EntityKind: kind, Facts: facts}
	fc.CompileFields(kubernetesBuiltinFacts())
	return fc.Naming(), fc.Err()
}

// =============================================================================
// Facts from a TokenReview
// =============================================================================

func TestFacts_FromTokenReview(t *testing.T) {
	naming, err := compileFacts("", map[string]string{
		"username":                  "workload",
		"service_account_namespace": "ns",
		"groups":                    "groups",
	})
	require.NoError(t, err)

	status := &tokenReviewStatus{
		Authenticated: true,
		User: tokenReviewUser{
			Username: "system:serviceaccount:ci:deployer",
			UID:      "4f7c-uid",
			Groups:   []string{"system:serviceaccounts", "system:serviceaccounts:ci", "system:authenticated"},
		},
		Audiences: []string{"warden", "vault"},
	}
	adm := newAdmission(status, "ci", "deployer", map[string]any{"iat": 1700000000.0, "team": "core"}, nil)

	// The table copies what it is given.
	status.User.Groups[0] = "changed"
	status.Audiences[0] = "changed"

	cases := []struct {
		name string
		want []string
	}{
		{"service_account_namespace", []string{"ci"}},
		{"service_account_name", []string{"deployer"}},
		{"service_account_uid", []string{"4f7c-uid"}},
		{"username", []string{"system:serviceaccount:ci:deployer"}},
		{"groups", []string{"system:serviceaccounts", "system:serviceaccounts:ci", "system:authenticated"}},
		{"aud", []string{"warden", "vault"}},
		{"workload", []string{"system:serviceaccount:ci:deployer"}},
		{"ns", []string{"ci"}},
		{"kind", []string{logical.EntityKindAgent}},
		{"mount", nil}, // set by core at LoginCreateToken
		{"team", nil},  // a token claim is not a fact
		{"iat", nil},
		{"email", nil},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, factstest.Values(adm, naming, tc.name), "fact %q", tc.name)
	}

	assert.Equal(t, map[string]string{
		"workload": "system:serviceaccount:ci:deployer",
		"ns":       "ci",
		"groups":   "system:serviceaccounts,system:serviceaccounts:ci,system:authenticated",
	}, adm.RenderMetadata(naming))

	assert.Equal(t, time.Unix(1700000000, 0), adm.IssuedAt)
	assert.Nil(t, adm.Mount)
	assert.Empty(t, adm.MountPath)
	want := len("service_account_namespace") + len("ci") +
		len("service_account_name") + len("deployer") +
		len("service_account_uid") + len("4f7c-uid") +
		len("username") + len("system:serviceaccount:ci:deployer") +
		len("groups") + len("system:serviceaccounts") + len("system:serviceaccounts:ci") + len("system:authenticated") +
		len("aud") + len("warden") + len("vault")
	assert.Equal(t, int64(want), adm.Bytes)
	assert.Equal(t, int64(want), adm.Size())

	// A username the API server would not split as a service account admits
	// nothing, even for a role that binds any name in the namespace (before,
	// "default:myapp:extra" was admitted as the name "myapp:extra").
	for _, username := range []string{
		"system:serviceaccount:default:myapp:extra",
		"system:serviceaccount:default:",
		"system:serviceaccount::myapp",
		"system:serviceaccount:Default:myapp",
		"system:serviceaccount:default:MyApp",
		"system:node:worker-1",
	} {
		t.Run(username, func(t *testing.T) {
			b, _ := loginSetup(t, tokenReviewStatus{
				Authenticated: true,
				User:          tokenReviewUser{Username: username},
			}, nil)
			require.NoError(t, b.setRole(context.Background(), &KubernetesRole{
				Name:                          "anyname",
				BoundServiceAccountNames:      []string{"*"},
				BoundServiceAccountNamespaces: []string{"default", "Default"},
				TokenPolicies:                 []string{"p"},
				TokenTTL:                      "1h",
				TokenType:                     "kubernetes_role",
			}))
			resp := login(t, b, mintJWT(map[string]any{"sub": username}), "anyname")
			require.Error(t, resp.Err)
			assert.Nil(t, resp.Auth)
		})
	}
}

// An empty value is not a fact, and an iat that is absent or not a number
// leaves IssuedAt zero.
func TestFacts_EmptyValuesAndIssuedAt(t *testing.T) {
	naming, err := compileFacts("", nil)
	require.NoError(t, err)
	status := &tokenReviewStatus{
		Authenticated: true,
		User:          tokenReviewUser{Username: "system:serviceaccount:ci:deployer", Groups: []string{"", "a", ""}},
		Audiences:     []string{""},
	}
	adm := newAdmission(status, "ci", "deployer", nil, nil)
	assert.Empty(t, factstest.Values(adm, naming, "service_account_uid"))
	assert.Equal(t, []string{"a"}, factstest.Values(adm, naming, "groups"))
	assert.Empty(t, factstest.Values(adm, naming, "aud"))
	assert.True(t, adm.IssuedAt.IsZero())

	for _, claims := range []map[string]any{
		{},
		{"iat": "1700000000"},
		{"iat": -5.0},
	} {
		assert.True(t, newAdmission(status, "ci", "deployer", claims, nil).IssuedAt.IsZero(), "claims %v", claims)
	}
}

// FactsConfig is flattened into the config's own keys on the way in and on the
// way to storage; bound_audiences is read from a list or a comma-separated
// string.
func TestFactsConfig_JSONFlattened(t *testing.T) {
	cfg, err := mapToKubernetesAuthConfig(map[string]any{
		"kubernetes_host": "https://kube",
		"entity_kind":     "human",
		"facts":           map[string]any{"username": "workload"},
		"bound_audiences": "warden, vault",
	})
	require.NoError(t, err)
	assert.Equal(t, "human", cfg.EntityKind)
	assert.Equal(t, map[string]string{"username": "workload"}, cfg.Facts)
	assert.Equal(t, []string{"warden", "vault"}, cfg.BoundAudiences)

	cfg, err = mapToKubernetesAuthConfig(map[string]any{"bound_audiences": []any{"warden"}})
	require.NoError(t, err)
	assert.Equal(t, []string{"warden"}, cfg.BoundAudiences)

	_, err = mapToKubernetesAuthConfig(map[string]any{"bound_audiences": map[string]any{"a": 1}})
	assert.ErrorContains(t, err, "bound_audiences:")

	raw, err := json.Marshal(normalizedConfig(&KubernetesAuthConfig{
		KubernetesHost: "https://kube",
		BoundAudiences: []string{"warden"},
		FactsConfig:    helper.FactsConfig{EntityKind: "human", Facts: map[string]string{"username": "workload"}},
	}))
	require.NoError(t, err)
	var flat map[string]any
	require.NoError(t, json.Unmarshal(raw, &flat))
	assert.Equal(t, "human", flat["entity_kind"])
	assert.Equal(t, map[string]any{"username": "workload"}, flat["facts"])
	assert.Equal(t, []any{"warden"}, flat["bound_audiences"])
	assert.NotContains(t, flat, "FactsConfig")
}

func TestFactNames(t *testing.T) {
	b := reviewingBackend(t, nil)
	builtins := []string{"aud", "groups", "service_account_name", "service_account_namespace", "service_account_uid", "username"}
	assert.Equal(t, builtins, b.FactNames())

	require.Equal(t, http.StatusOK, writeConfig(b, map[string]any{
		"facts": map[string]any{"username": "workload"},
	}).StatusCode)
	names := b.FactNames()
	assert.Equal(t, append(slices.Clone(builtins), "workload"), names)

	// The result is the caller's: changing it leaves the mount's alone.
	names[0] = "changed"
	assert.Equal(t, "aud", b.FactNames()[0])

	unconfigured, _ := newTestBackend(t)
	assert.Empty(t, unconfigured.FactNames())

	// The facts field names the sources a kubernetes mount has, and no pointers.
	desc := b.pathConfig().Fields["facts"].Description
	for _, name := range builtins {
		assert.Contains(t, desc, name)
	}
	assert.NotContains(t, desc, "Pointer")
}

// =============================================================================
// Login carries the admission alongside today's role logic
// =============================================================================

func TestLogin_CarriesAdmission(t *testing.T) {
	b, fake := loginSetup(t, tokenReviewStatus{
		Authenticated: true,
		User: tokenReviewUser{
			Username: "system:serviceaccount:default:myapp",
			UID:      "uid-1",
			Groups:   []string{"system:serviceaccounts", "system:serviceaccounts:default", "system:authenticated"},
		},
		Audiences: []string{"warden"},
	}, map[string]any{
		"facts":           map[string]any{"username": "workload"},
		"bound_audiences": []string{"warden", "other"},
	})
	ctx := context.Background()
	resp, err := b.handleRoleCreate(ctx, nil, roleFieldData(t, b, map[string]any{
		"name":                             "auditor",
		"bound_service_account_names":      []string{"myapp"},
		"bound_service_account_namespaces": []string{"default"},
		"audience":                         "warden",
		"max_age":                          "10m",
		"token_policies":                   []string{"audit"},
		"metadata_mappings":                map[string]any{"groups": "groups", "service_account_name": "sa"},
	}))
	require.NoError(t, err)
	require.Nil(t, resp.Err)

	iat := time.Now().Add(-time.Minute).Unix()
	token := mintJWT(map[string]any{"sub": "system:serviceaccount:default:myapp", "iat": iat})
	resp = login(t, b, token, "auditor")
	require.Equal(t, http.StatusOK, resp.StatusCode, "login: %v", resp.Err)
	auth := resp.Auth
	require.NotNil(t, auth)

	// Today's role output is untouched, and bound_audiences is not sent yet:
	// the review carries the role's audience only.
	assert.Equal(t, "auditor", auth.RoleName)
	assert.Equal(t, []string{"audit"}, auth.Policies)
	assert.Equal(t, "system:serviceaccount:default:myapp", auth.PrincipalID)
	assert.Equal(t, map[string]string{
		"groups": "system:serviceaccounts,system:serviceaccounts:default,system:authenticated",
		"sa":     "myapp",
	}, auth.Metadata)
	assert.Equal(t, []string{"warden"}, fake.AudsSeen)

	adm := auth.Admission
	require.NotNil(t, adm)
	assert.Same(t, b.mountFacts, adm.Mount, "the admission shares the mount's live naming")
	assert.Empty(t, adm.MountPath, "core names the mount")
	assert.Equal(t, time.Unix(iat, 0), adm.IssuedAt)
	assert.Equal(t, adm.Facts.(*selector.Table).Bytes(), adm.Bytes)
	assert.Positive(t, adm.Size())

	n := adm.Mount.Load()
	assert.Equal(t, []string{"default"}, factstest.Values(adm, n, "service_account_namespace"))
	assert.Equal(t, []string{"myapp"}, factstest.Values(adm, n, "service_account_name"))
	assert.Equal(t, []string{"uid-1"}, factstest.Values(adm, n, "service_account_uid"))
	assert.Equal(t, []string{"system:serviceaccount:default:myapp"}, factstest.Values(adm, n, "workload"))
	assert.Len(t, factstest.Values(adm, n, "groups"), 3)
	assert.Equal(t, []string{"warden"}, factstest.Values(adm, n, "aud"))

	// A role without an audience sends none, whatever bound_audiences holds.
	require.Equal(t, http.StatusOK, login(t, b, token, "myrole").StatusCode)
	assert.Empty(t, fake.AudsSeen)
}

// The claims are parsed on every login, with or without max_age, so IssuedAt
// costs no extra parse; a token without a readable iat leaves it zero.
func TestLogin_IssuedAt(t *testing.T) {
	b, _ := loginSetup(t, tokenReviewStatus{
		Authenticated: true,
		User:          tokenReviewUser{Username: "system:serviceaccount:default:myapp"},
	}, nil)
	cases := []struct {
		name  string
		token string
		want  time.Time
	}{
		{"iat", mintJWT(map[string]any{"iat": 1700000000}), time.Unix(1700000000, 0)},
		{"no iat", mintJWT(map[string]any{"sub": "x"}), time.Time{}},
		{"string iat", mintJWT(map[string]any{"iat": "1700000000"}), time.Time{}},
		{"not a JWT", "opaque-token", time.Time{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := login(t, b, tc.token, "myrole")
			require.Equal(t, http.StatusOK, resp.StatusCode, "login: %v", resp.Err)
			require.NotNil(t, resp.Auth.Admission)
			assert.Equal(t, tc.want, resp.Auth.Admission.IssuedAt)
		})
	}
}

// A refused login carries no admission.
func TestLogin_RefusedCarriesNoAdmission(t *testing.T) {
	b := reviewingBackend(t, nil)
	for _, token := range []string{
		saToken("default", "other", []string{apiServerAudience}, nil), // not bound
		saToken("default", "myapp", []string{"elsewhere"}, nil),       // review refused
	} {
		resp := login(t, b, token, "reader")
		require.Error(t, resp.Err)
		assert.Nil(t, resp.Auth)
	}
	resp := login(t, b, saToken("default", "myapp", []string{apiServerAudience}, nil), "reader")
	require.Equal(t, http.StatusOK, resp.StatusCode, "login: %v", resp.Err)
	assert.NotNil(t, resp.Auth.Admission)
}

// =============================================================================
// Metadata equivalence: the mapping renders what metadata_mappings extracts
// =============================================================================

func TestRenderMetadata_EquivalentToExtractK8sMetadata(t *testing.T) {
	type review struct {
		ns, name, uid string
		groups        []string
	}
	check := func(t *testing.T, r review, mapping map[string]string) {
		t.Helper()
		username := serviceAccountUsernamePrefix + r.ns + ":" + r.name
		want := extractK8sMetadata(mapping, r.ns, r.name, r.uid, username, r.groups)
		naming, err := compileFacts("", mapping)
		require.NoError(t, err)
		status := &tokenReviewStatus{Authenticated: true, User: tokenReviewUser{Username: username, UID: r.uid, Groups: r.groups}}
		assert.Equal(t, want, newAdmission(status, r.ns, r.name, nil, nil).RenderMetadata(naming), "review %+v, mapping %v", r, mapping)
	}

	full := review{"ci", "deployer", "uid-7", []string{"system:serviceaccounts", "system:serviceaccounts:ci", "system:authenticated"}}
	cases := []struct {
		name    string
		review  review
		mapping map[string]string
	}{
		{"every field", full, map[string]string{
			"service_account_namespace": "ns", "service_account_name": "sa",
			"service_account_uid": "uid", "username": "workload", "groups": "teams",
		}},
		{"identity mappings", full, map[string]string{"groups": "groups", "username": "username"}},
		{"no mappings", full, nil},
		{"one group", review{"ci", "deployer", "uid-7", []string{"g"}}, map[string]string{"groups": "teams"}},
		{"no groups", review{"ci", "deployer", "uid-7", nil}, map[string]string{"groups": "teams", "username": "who"}},
		{"empty uid skipped", review{"ci", "deployer", "", nil}, map[string]string{"service_account_uid": "uid"}},
		{"everything absent", review{"ci", "deployer", "", nil}, map[string]string{"service_account_uid": "uid", "groups": "teams"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { check(t, tc.review, tc.mapping) })
	}

	// Generated reviews and mappings: any subset of fields, each to a distinct
	// name or to itself.
	rng := rand.New(rand.NewSource(20261020))
	sources := kubernetesBuiltinFacts()
	sources = slices.DeleteFunc(sources, func(s string) bool { return s == factAudiences }) // not a metadata_mappings source
	targets := []string{"workload", "team", "who", "id", "where"}
	for i := 0; i < 300; i++ {
		r := review{ns: []string{"ci", "prod"}[rng.Intn(2)], name: []string{"a", "deployer"}[rng.Intn(2)]}
		if rng.Intn(3) > 0 {
			r.uid = fmt.Sprintf("uid-%d", rng.Intn(100))
		}
		for j := rng.Intn(4); j > 0; j-- {
			r.groups = append(r.groups, fmt.Sprintf("g%d", rng.Intn(5)))
		}
		mapping := map[string]string{}
		free := slices.Clone(targets)
		for _, s := range sources {
			switch rng.Intn(3) {
			case 1:
				mapping[s] = s
			case 2:
				k := rng.Intn(len(free))
				mapping[s] = free[k]
				free = slices.Delete(free, k, k+1)
			}
		}
		check(t, r, mapping)
	}
}

// The one difference: an empty group name is not a fact, so it is dropped from
// the rendering where today's extractor keeps its comma. Kubernetes does not
// assert empty group names.
func TestRenderMetadata_EmptyGroupEntry(t *testing.T) {
	mapping := map[string]string{"groups": "teams"}
	groups := []string{"a", ""}
	assert.Equal(t, map[string]string{"teams": "a,"}, extractK8sMetadata(mapping, "ci", "x", "", "u", groups))
	naming, err := compileFacts("", mapping)
	require.NoError(t, err)
	status := &tokenReviewStatus{User: tokenReviewUser{Username: "u", Groups: groups}}
	assert.Equal(t, map[string]string{"teams": "a"}, newAdmission(status, "ci", "x", nil, nil).RenderMetadata(naming))
}

// =============================================================================
// Config: entity_kind, facts and bound_audiences
// =============================================================================

func TestConfigWrite_FactsAndAudiences(t *testing.T) {
	b := reviewingBackend(t, nil)
	ctx := context.Background()

	read := func() map[string]any {
		resp, err := b.handleConfigRead(ctx, &logical.Request{}, &framework.FieldData{})
		require.NoError(t, err)
		return resp.Data
	}
	assert.Equal(t, logical.EntityKindAgent, read()["entity_kind"], "agent by default")
	assert.Empty(t, read()["facts"])
	assert.Empty(t, read()["bound_audiences"])

	require.Equal(t, http.StatusOK, writeConfig(b, map[string]any{
		"entity_kind":     "human",
		"facts":           map[string]any{"username": "workload", "groups": "teams"},
		"bound_audiences": []string{"warden", "vault"},
	}).StatusCode)
	data := read()
	assert.Equal(t, "human", data["entity_kind"])
	assert.Equal(t, map[string]string{"username": "workload", "groups": "teams"}, data["facts"])
	assert.Equal(t, []string{"warden", "vault"}, data["bound_audiences"])
	n := b.mountFacts.Load()
	require.NotNil(t, n)
	assert.Equal(t, "human", n.Kind)
	assert.Equal(t, []string{"teams", "workload"}, n.Mapping.Mapped())

	// The read is a copy.
	data["bound_audiences"].([]string)[0] = "changed"
	assert.Equal(t, []string{"warden", "vault"}, b.config.BoundAudiences)

	// A write that leaves them out keeps them.
	require.Equal(t, http.StatusOK, writeConfig(b, map[string]any{"issuer": "https://kube"}).StatusCode)
	assert.Equal(t, []string{"teams", "workload"}, b.mountFacts.Load().Mapping.Mapped())
	assert.Equal(t, "human", b.mountFacts.Load().Kind)
	assert.Equal(t, []string{"warden", "vault"}, b.config.BoundAudiences)

	// The stored config reloads into the same naming and audiences.
	entry, err := b.storageView.Get(ctx, "config")
	require.NoError(t, err)
	var stored map[string]any
	require.NoError(t, entry.DecodeJSON(&stored))
	assert.Equal(t, "human", stored["entity_kind"])
	assert.Equal(t, map[string]any{"username": "workload", "groups": "teams"}, stored["facts"])
	assert.Equal(t, []any{"warden", "vault"}, stored["bound_audiences"])
	reloaded, _ := newTestBackend(t)
	reloaded.storageView = b.storageView
	require.NoError(t, reloaded.Initialize(ctx))
	assert.Equal(t, b.mountFacts.Load().Kind, reloaded.mountFacts.Load().Kind)
	assert.Equal(t, b.mountFacts.Load().Mapping.Names(), reloaded.mountFacts.Load().Mapping.Names())
	assert.Equal(t, []string{"warden", "vault"}, reloaded.config.BoundAudiences)

	// A comma-separated string is a list; an empty value clears the list and
	// an empty map the mapping.
	require.Equal(t, http.StatusOK, writeConfig(b, map[string]any{"bound_audiences": "a, b"}).StatusCode)
	assert.Equal(t, []string{"a", "b"}, b.config.BoundAudiences)
	require.Equal(t, http.StatusOK, writeConfig(b, map[string]any{
		"bound_audiences": "",
		"facts":           map[string]any{},
	}).StatusCode)
	assert.Empty(t, b.config.BoundAudiences)
	assert.Empty(t, b.mountFacts.Load().Mapping.Mapped())
	assert.Len(t, b.FactNames(), len(kubernetesBuiltinFacts()))
}

func TestConfigWrite_FactsAndAudiencesRefused(t *testing.T) {
	cases := []struct {
		name string
		raw  map[string]any
		want string
	}{
		{"bad name", map[string]any{"facts": map[string]any{"username": "Workload"}}, "facts:"},
		{"reserved mount", map[string]any{"facts": map[string]any{"username": "mount"}}, "reserved"},
		{"reserved kind", map[string]any{"facts": map[string]any{"groups": "kind"}}, "reserved"},
		{"two sources one name", map[string]any{"facts": map[string]any{"username": "workload", "service_account_uid": "workload"}},
			`fact "workload" is produced by both`},
		{"another source onto a built-in", map[string]any{"facts": map[string]any{"username": "aud"}}, "built-in"},
		{"not a field", map[string]any{"facts": map[string]any{"email": "email"}}, `source "email" is not a field of this mount`},
		{"a pointer", map[string]any{"facts": map[string]any{"/user/uid": "uid"}}, "is not a field of this mount"},
		{"non-string name", map[string]any{"facts": map[string]any{"username": 5}}, "must be a string"},
		{"unknown entity_kind", map[string]any{"entity_kind": "robot"}, "entity_kind:"},
		{"empty audience in a list", map[string]any{"bound_audiences": []string{"warden", ""}}, "bound_audiences: entry 1 is empty"},
		{"empty audience in a string", map[string]any{"bound_audiences": "warden,,vault"}, "bound_audiences: entry 1 is empty"},
		{"blank audience", map[string]any{"bound_audiences": []string{"  "}}, "bound_audiences: entry 0 is empty"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := reviewingBackend(t, map[string]any{
				"facts":           map[string]any{"username": "workload"},
				"bound_audiences": []string{"warden"},
			})
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

// A stored config whose facts do not compile (written under looser rules, or
// edited in storage) does not fail the mount: it is installed with no naming,
// so the mount answers no fact and nothing reading facts can match its
// admissions. Today's role logins are not affected by facts.
func TestNaming_LoadFailureAnswersNoFacts(t *testing.T) {
	ctx := context.Background()
	host := newReviewingAPIServer(t)
	bad := map[string]any{
		"kubernetes_host": host,
		"tls_skip_verify": true,
		"facts":           map[string]any{"email": "email"},
	}
	token := saToken("default", "myapp", []string{apiServerAudience}, nil)

	t.Run("from storage", func(t *testing.T) {
		b, _ := newTestBackend(t)
		entry, err := sdklogical.StorageEntryJSON("config", bad)
		require.NoError(t, err)
		require.NoError(t, b.storageView.Put(ctx, entry))
		require.NoError(t, b.setRole(ctx, &KubernetesRole{
			Name: "reader", BoundServiceAccountNames: []string{"myapp"},
			BoundServiceAccountNamespaces: []string{"default"}, TokenPolicies: []string{"read"},
		}))

		require.NoError(t, b.Initialize(ctx), "a bad mapping does not fail the load")
		require.NotNil(t, b.config)
		require.Error(t, b.config.FactsConfig.Err())
		assert.Nil(t, b.mountFacts.Load())
		assert.Empty(t, b.FactNames())

		resp := login(t, b, token, "reader")
		require.Equal(t, http.StatusOK, resp.StatusCode, "role logins do not read facts: %v", resp.Err)
		assert.Equal(t, []string{"read"}, resp.Auth.Policies)
		adm := resp.Auth.Admission
		require.NotNil(t, adm)
		adm.MountPath = "auth/kubernetes/"
		for _, name := range append(kubernetesBuiltinFacts(), "mount", "kind") {
			assert.Empty(t, factstest.Values(adm, adm.Mount.Load(), name), "fact %q", name)
		}

		// A write that leaves the stored facts in place is told how to replace
		// them, and changes nothing.
		before := b.config
		resp = writeConfig(b, map[string]any{"issuer": "https://kube"})
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
		assert.EqualError(t, resp.Err, `the stored facts do not compile (facts: source "email" is not a field of this mount (one of aud, groups, service_account_name, service_account_namespace, service_account_uid, username)); send facts (and entity_kind) in this write to replace them`)
		assert.Same(t, before, b.config)

		// Rewriting the facts restores the naming, for this admission too.
		require.Equal(t, http.StatusOK, writeConfig(b, map[string]any{"facts": map[string]any{}}).StatusCode)
		assert.Equal(t, []string{"myapp"}, factstest.Values(adm, adm.Mount.Load(), "service_account_name"))
	})

	t.Run("from the mount table", func(t *testing.T) {
		backend, err := Factory(ctx, &logical.BackendConfig{Logger: testLogger(), Config: bad})
		require.NoError(t, err, "a bad mapping does not fail the mount")
		b := backend.(*kubernetesAuthBackend)
		require.Error(t, b.config.FactsConfig.Err())
		assert.Nil(t, b.mountFacts.Load())
	})
}

// The naming is published with the config it was compiled from, in one
// critical section: a reader holding configMu sees them agree, a lock-free
// reader sees one published naming whole, and logins racing config writes all
// share the mount's MountFacts.
func TestNaming_PublishNeverHalfApplied(t *testing.T) {
	b := reviewingBackend(t, nil)
	token := saToken("default", "myapp", []string{apiServerAudience}, nil)
	writes := []map[string]any{
		{"entity_kind": "agent", "facts": map[string]any{"username": "workload"}},
		{"entity_kind": "human", "facts": map[string]any{"groups": "teams", "service_account_name": "sa"}},
	}
	whole := func(n *logical.MountNaming) bool {
		switch n.Kind {
		case logical.EntityKindAgent:
			return slices.Equal(n.Mapping.Mapped(), []string{"workload"})
		case logical.EntityKindHuman:
			return slices.Equal(n.Mapping.Mapped(), []string{"sa", "teams"})
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

	builtins := len(kubernetesBuiltinFacts())
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
				if len(names) != builtins+1 && len(names) != builtins+2 {
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
				resp := login(t, b, token, "reader")
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
				if n.Kind == logical.EntityKindAgent && len(factstest.Values(adm, n, "workload")) != 1 {
					report("agent naming lost workload")
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

// convertRole converts one role on a mount to a selector rule, given the
// audiences the mount sends to TokenReview (the union over its roles; empty
// when it sends none). A bound list holding "*" matches any value today, so it
// omits the name; any other list becomes its escaped values. The role's
// audience becomes an "aud" rule. A role without one was reviewed against the
// API server's own audience; when the mount sends a union, the review no longer
// checks that audience, so the rule asks for it in "aud" (and the union must
// carry it). The rule pins the mount.
func convertRole(t *testing.T, mountPath string, role *KubernetesRole, mountAudiences []string) *selector.Rule {
	t.Helper()
	rule := map[string][]string{"mount": {mountPath}}
	bind := func(name string, list []string) {
		if slices.Contains(list, "*") {
			return
		}
		for _, v := range list {
			rule[name] = append(rule[name], escapeValue(v))
		}
	}
	bind(factServiceAccountName, role.BoundServiceAccountNames)
	bind(factServiceAccountNamespace, role.BoundServiceAccountNamespaces)
	switch {
	case role.Audience != "":
		rule[factAudiences] = []string{escapeValue(role.Audience)}
	case len(mountAudiences) > 0:
		require.Contains(t, mountAudiences, apiServerAudience)
		rule[factAudiences] = []string{escapeValue(apiServerAudience)}
	}
	compiled, err := selector.Compile(rule)
	require.NoError(t, err)
	return compiled
}

// maxAgeHolds is the converted max_age: the admission's IssuedAt is known and
// no older than maxAge at now. Zero maxAge is no bound.
func maxAgeHolds(adm *logical.Admission, maxAge time.Duration, now time.Time) bool {
	if maxAge == 0 {
		return true
	}
	return !adm.IssuedAt.IsZero() && now.Sub(adm.IssuedAt) <= maxAge
}

// admitConverted runs the converted model for token: a TokenReview with the
// mount's audiences, the admission built as a login builds it, the rule
// matched through the naming, and the max_age bound on IssuedAt.
func admitConverted(t *testing.T, b *kubernetesAuthBackend, token string, mountAudiences []string, rule *selector.Rule, naming *logical.MountNaming, maxAge time.Duration) bool {
	t.Helper()
	cfg := b.config
	status, err := reviewToken(context.Background(), cfg.httpClient, cfg.KubernetesHost, token, token, mountAudiences)
	if err != nil || !status.Authenticated || status.Error != "" {
		return false
	}
	ns, name, ok := parseSAUsername(status.User.Username)
	if !ok {
		return false
	}
	claims, _ := jwtparse.ParseJWTClaimsUnverified(token)
	adm := newAdmission(status, ns, name, claims, b.mountFacts)
	adm.MountPath = "auth/kubernetes/"
	return rule.Match(factstest.Source{Adm: adm, Naming: naming}) && maxAgeHolds(adm, maxAge, time.Now())
}

// TestEquivalence_RoleMatcherAndConvertedRule checks, over generated service
// accounts, token audiences and roles, that today's login accepts a token
// exactly when the converted model does. Today's side is the real login: the
// TokenReview with the role's audience, matchRoleBindings and the max_age
// check on the token's iat. The converted side reviews with the mount's
// audiences and matches the converted rule and max_age on the admission.
//
// The domain is the one where the conversion is exact: every token carries an
// iat (see TestEquivalence_MaxAgeStricter for one that does not), and no bound
// list is empty (today such a list matches nothing; a rule cannot say so).
// Roles that bind both lists to "*" are stored directly: role validation
// refuses them today, and a group carrying the converted rule is only warned.
func TestEquivalence_RoleMatcherAndConvertedRule(t *testing.T) {
	ctx := context.Background()
	b := reviewingBackend(t, nil)
	naming, err := compileFacts("", nil)
	require.NoError(t, err)

	rng := rand.New(rand.NewSource(20261020))
	pick := func(pool []string) string { return pool[rng.Intn(len(pool))] }
	names := []string{"myapp", "deployer", "ci-bot"}
	namespaces := []string{"default", "ci", "prod"}
	tokenAudiences := []string{apiServerAudience, "warden", "vault"}
	extraAudiences := []string{"warden", "vault", "other"}
	boundList := func(pool []string) []string {
		out := make([]string, 1+rng.Intn(2))
		for i := range out {
			if rng.Intn(5) == 0 {
				out[i] = "*"
			} else {
				out[i] = pick(pool)
			}
		}
		return out
	}
	maxAges := []time.Duration{time.Minute, 10 * time.Minute, time.Hour}

	var accepted, refused, wildcards, unions, aged int
	for i := 0; i < 1000; i++ {
		var auds []string
		for _, a := range tokenAudiences {
			if rng.Intn(5) < 3 {
				auds = append(auds, a)
			}
		}
		role := &KubernetesRole{
			Name:                          "r",
			BoundServiceAccountNames:      boundList(names),
			BoundServiceAccountNamespaces: boundList(namespaces),
			TokenPolicies:                 []string{"p"},
			TokenTTL:                      "1h",
			TokenType:                     "kubernetes_role",
		}
		if rng.Intn(2) == 0 {
			role.Audience = pick(tokenAudiences)
		}
		var maxAge time.Duration
		age := time.Duration(rng.Intn(120)) * time.Minute
		if rng.Intn(2) == 0 {
			maxAge = maxAges[rng.Intn(len(maxAges))]
			role.MaxAge = maxAge.String()
			// Far from the boundary on either side, so the two clocks agree.
			age = maxAge / 2
			if rng.Intn(2) == 0 {
				age = 2 * maxAge
			}
			aged++
		}
		if slices.Contains(role.BoundServiceAccountNames, "*") || slices.Contains(role.BoundServiceAccountNamespaces, "*") {
			wildcards++
		}

		// The mount's audiences: the role's plus other roles', or, for a role
		// without one, nothing or a union carrying the API server's.
		var mountAudiences []string
		if role.Audience != "" || rng.Intn(2) == 0 {
			if role.Audience != "" {
				mountAudiences = append(mountAudiences, role.Audience)
			} else {
				mountAudiences = append(mountAudiences, apiServerAudience)
			}
			for j := rng.Intn(3); j > 0; j-- {
				mountAudiences = append(mountAudiences, pick(extraAudiences))
			}
			if len(mountAudiences) > 1 {
				unions++
			}
		}

		token := saToken(pick(namespaces), pick(names), auds, map[string]any{
			"iat": time.Now().Add(-age).Unix(),
		})
		require.NoError(t, b.setRole(ctx, role))

		// Today: the real login.
		resp := login(t, b, token, role.Name)
		old := resp.Err == nil && resp.Auth != nil

		// Converted.
		rule := convertRole(t, "auth/kubernetes/", role, mountAudiences)
		got := admitConverted(t, b, token, mountAudiences, rule, naming, maxAge)

		require.Equal(t, old, got, "sample %d: token audiences %v, role %+v, mount audiences %v, age %v",
			i, auds, role, mountAudiences, age)
		if old {
			accepted++
		} else {
			refused++
		}
	}
	// Both outcomes and every feature are exercised, so agreement is not vacuous.
	t.Logf("accepted %d, refused %d, wildcards %d, unions %d, max_age %d", accepted, refused, wildcards, unions, aged)
	assert.Greater(t, accepted, 30)
	assert.Greater(t, refused, 30)
	assert.Greater(t, wildcards, 30)
	assert.Greater(t, unions, 30)
	assert.Greater(t, aged, 30)
}

// The documented difference: max_age is stricter once converted. Today a token
// whose iat is absent or not a number passes max_age (and the check runs once,
// at login); the converted bound needs a known IssuedAt, so it refuses.
func TestEquivalence_MaxAgeStricter(t *testing.T) {
	ctx := context.Background()
	b := reviewingBackend(t, nil)
	naming, err := compileFacts("", nil)
	require.NoError(t, err)
	role := &KubernetesRole{
		Name:                          "aged",
		BoundServiceAccountNames:      []string{"myapp"},
		BoundServiceAccountNamespaces: []string{"default"},
		MaxAge:                        "10m",
		TokenPolicies:                 []string{"p"},
		TokenTTL:                      "1h",
		TokenType:                     "kubernetes_role",
	}
	require.NoError(t, b.setRole(ctx, role))
	rule := convertRole(t, "auth/kubernetes/", role, nil)

	cases := []struct {
		name     string
		iat      any // nil: no iat claim
		old, new bool
	}{
		{"fresh iat", time.Now().Add(-time.Minute).Unix(), true, true},
		{"stale iat", time.Now().Add(-time.Hour).Unix(), false, false},
		{"no iat", nil, true, false},
		{"iat not a number", "1700000000", true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			extra := map[string]any{}
			if tc.iat != nil {
				extra["iat"] = tc.iat
			}
			token := saToken("default", "myapp", []string{apiServerAudience}, extra)
			resp := login(t, b, token, role.Name)
			assert.Equal(t, tc.old, resp.Err == nil && resp.Auth != nil, "today's login")
			assert.Equal(t, tc.new, admitConverted(t, b, token, nil, rule, naming, 10*time.Minute), "converted")
		})
	}
}
