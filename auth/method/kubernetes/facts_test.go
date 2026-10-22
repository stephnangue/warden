package kubernetes

import (
	"context"
	"encoding/json"
	"fmt"
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
// reviewing API server plus extra config keys.
func reviewingBackend(t *testing.T, extra map[string]any) *kubernetesAuthBackend {
	t.Helper()
	b, _ := newTestBackend(t)
	raw := map[string]any{"kubernetes_host": newReviewingAPIServer(t), "tls_skip_verify": true}
	for k, v := range extra {
		raw[k] = v
	}
	resp := writeConfig(b, raw)
	require.Equal(t, http.StatusOK, resp.StatusCode, "config write: %v", resp.Err)
	return b
}

func login(t testing.TB, b *kubernetesAuthBackend, token string) *logical.Response {
	t.Helper()
	resp, err := b.handleLogin(context.Background(), &logical.Request{}, &framework.FieldData{
		Raw:    map[string]any{"jwt": token},
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
	// nothing (before, "default:myapp:extra" was admitted as the name
	// "myapp:extra").
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
			resp := login(t, b, mintJWT(map[string]any{"sub": username}))
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
// Login is an admission
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
		"max_age":         "10m",
	})

	iat := time.Now().Add(-time.Minute).Unix()
	token := mintJWT(map[string]any{"sub": "system:serviceaccount:default:myapp", "iat": iat})
	resp := login(t, b, token)
	require.Equal(t, http.StatusOK, resp.StatusCode, "login: %v", resp.Err)
	auth := resp.Auth
	require.NotNil(t, auth)

	// An admission: no policies, no metadata; the review carries the mount's
	// bound_audiences.
	assert.Nil(t, auth.Policies)
	assert.Nil(t, auth.Metadata)
	assert.Equal(t, logical.TokenTypeIdentity, auth.TokenType)
	assert.Equal(t, logical.CredentialFormatKubernetesJWT, b.CredentialFormat())
	assert.Equal(t, "system:serviceaccount:default:myapp", auth.PrincipalID)
	assert.Equal(t, []string{"warden", "other"}, fake.AudsSeen)

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
			resp := login(t, b, tc.token)
			require.Equal(t, http.StatusOK, resp.StatusCode, "login: %v", resp.Err)
			require.NotNil(t, resp.Auth.Admission)
			assert.Equal(t, tc.want, resp.Auth.Admission.IssuedAt)
		})
	}
}

// A refused login carries no admission.
func TestLogin_RefusedCarriesNoAdmission(t *testing.T) {
	b := reviewingBackend(t, map[string]any{"max_age": "10m"})
	for _, token := range []string{
		saToken("default", "myapp", []string{"elsewhere"}, nil),                                                            // review refused
		saToken("default", "myapp", []string{apiServerAudience}, map[string]any{"iat": time.Now().Add(-time.Hour).Unix()}), // older than max_age
	} {
		resp := login(t, b, token)
		require.Error(t, resp.Err)
		assert.Nil(t, resp.Auth)
	}
	resp := login(t, b, saToken("default", "myapp", []string{apiServerAudience}, map[string]any{"iat": time.Now().Unix()}))
	require.Equal(t, http.StatusOK, resp.StatusCode, "login: %v", resp.Err)
	assert.NotNil(t, resp.Auth.Admission)
}

// =============================================================================
// Metadata equivalence: the mapping renders what metadata_mappings extracts
// =============================================================================

// metadataCase is a reviewed service account, a metadata_mappings mapping, and
// the metadata the removed role login rendered from them (Want, frozen).
type metadataCase struct {
	Name      string            `json:"name,omitempty"`
	Namespace string            `json:"namespace"`
	Account   string            `json:"account"`
	UID       string            `json:"uid,omitempty"`
	Groups    []string          `json:"groups,omitempty"`
	Mapping   map[string]string `json:"mapping,omitempty"`
	Want      map[string]string `json:"want,omitempty"`
}

var fullGroups = []string{"system:serviceaccounts", "system:serviceaccounts:ci", "system:authenticated"}

// metadataCases are written by hand; testdata/metadata_equivalence.json holds
// 300 more, generated from a fixed seed: any subset of the fields, each to a
// distinct name or to itself.
var metadataCases = []metadataCase{
	{Name: "every field", Namespace: "ci", Account: "deployer", UID: "uid-7", Groups: fullGroups,
		Mapping: map[string]string{
			"service_account_namespace": "ns", "service_account_name": "sa",
			"service_account_uid": "uid", "username": "workload", "groups": "teams",
		},
		Want: map[string]string{
			"ns": "ci", "sa": "deployer", "uid": "uid-7", "workload": "system:serviceaccount:ci:deployer",
			"teams": "system:serviceaccounts,system:serviceaccounts:ci,system:authenticated",
		}},
	{Name: "identity mappings", Namespace: "ci", Account: "deployer", UID: "uid-7", Groups: fullGroups,
		Mapping: map[string]string{"groups": "groups", "username": "username"},
		Want: map[string]string{
			"groups":   "system:serviceaccounts,system:serviceaccounts:ci,system:authenticated",
			"username": "system:serviceaccount:ci:deployer",
		}},
	{Name: "no mappings", Namespace: "ci", Account: "deployer", UID: "uid-7", Groups: fullGroups},
	{Name: "one group", Namespace: "ci", Account: "deployer", UID: "uid-7", Groups: []string{"g"},
		Mapping: map[string]string{"groups": "teams"}, Want: map[string]string{"teams": "g"}},
	{Name: "no groups", Namespace: "ci", Account: "deployer", UID: "uid-7",
		Mapping: map[string]string{"groups": "teams", "username": "who"},
		Want:    map[string]string{"who": "system:serviceaccount:ci:deployer"}},
	{Name: "empty uid skipped", Namespace: "ci", Account: "deployer",
		Mapping: map[string]string{"service_account_uid": "uid"}},
	{Name: "everything absent", Namespace: "ci", Account: "deployer",
		Mapping: map[string]string{"service_account_uid": "uid", "groups": "teams"}},
}

// The mapping renders what the role's metadata_mappings extracted.
func TestRenderMetadata_EquivalentToExtractK8sMetadata(t *testing.T) {
	check := func(t *testing.T, c metadataCase) {
		t.Helper()
		username := serviceAccountUsernamePrefix + c.Namespace + ":" + c.Account
		naming, err := compileFacts("", c.Mapping)
		require.NoError(t, err)
		status := &tokenReviewStatus{Authenticated: true, User: tokenReviewUser{Username: username, UID: c.UID, Groups: c.Groups}}
		assert.Equal(t, c.Want, newAdmission(status, c.Namespace, c.Account, nil, nil).RenderMetadata(naming), "case %+v", c)
	}
	for _, c := range metadataCases {
		t.Run(c.Name, func(t *testing.T) { check(t, c) })
	}
	for _, c := range factstest.Frozen[metadataCase](t, "metadata_equivalence.json") {
		check(t, c)
	}
}

// The one difference: an empty group name is not a fact, so it is dropped from
// the rendering where the role login's extractor kept its comma ("a,").
// Kubernetes does not assert empty group names.
func TestRenderMetadata_EmptyGroupEntry(t *testing.T) {
	mapping := map[string]string{"groups": "teams"}
	groups := []string{"a", ""}
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
// admissions. Logins themselves are not refused over facts.
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

		require.NoError(t, b.Initialize(ctx), "a bad mapping does not fail the load")
		require.NotNil(t, b.config)
		require.Error(t, b.config.FactsConfig.Err())
		assert.Nil(t, b.mountFacts.Load())
		assert.Empty(t, b.FactNames())

		resp := login(t, b, token)
		require.Equal(t, http.StatusOK, resp.StatusCode, "logins do not read facts: %v", resp.Err)
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
// Equivalence: the removed role matcher (frozen) and the role converted to a
// selector rule
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
func convertRole(t *testing.T, mountPath string, role k8sRole, mountAudiences []string) *selector.Rule {
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
	bind(factServiceAccountName, role.Names)
	bind(factServiceAccountNamespace, role.Namespaces)
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

// k8sRole is what a removed kubernetes auth role bound a token to.
type k8sRole struct {
	Names      []string `json:"bound_service_account_names"`
	Namespaces []string `json:"bound_service_account_namespaces"`
	Audience   string   `json:"audience,omitempty"`
	MaxAge     string   `json:"max_age,omitempty"`
}

// k8sToken is a service-account token: its account, its aud claim, and how
// long before the test signs it it was issued (its iat).
type k8sToken struct {
	Namespace string   `json:"namespace"`
	Account   string   `json:"account"`
	Audiences []string `json:"aud,omitempty"`
	Age       string   `json:"age"`
}

// k8sCase is one frozen sample of the removed role login: a token, the role it
// was presented for, the audiences the converted mount sends to TokenReview
// (the union over its roles; empty when it sends none), and whether the role
// login accepted the token.
type k8sCase struct {
	Token          k8sToken `json:"token"`
	Role           k8sRole  `json:"role"`
	MountAudiences []string `json:"mount_audiences,omitempty"`
	Accepted       bool     `json:"accepted"`
}

// maxAgeOf parses a role's max_age; empty is no bound.
func maxAgeOf(t testing.TB, role k8sRole) time.Duration {
	t.Helper()
	if role.MaxAge == "" {
		return 0
	}
	d, err := time.ParseDuration(role.MaxAge)
	require.NoError(t, err)
	return d
}

// TestEquivalence_RoleMatcherAndConvertedRule checks, over the frozen cases in
// testdata/role_equivalence.json, that the converted model accepts a token
// exactly when the removed role login did. That login ran a TokenReview with
// the role's audience (none: the API server's), the role's service-account
// bindings ("*" matching any value), and the role's max_age against the
// token's iat. The converted side reviews with the mount's audiences and
// matches the converted rule and max_age on the admission.
//
// The cases were generated (1000, from a fixed seed) where the conversion is
// exact: every token carries an iat (see TestEquivalence_MaxAgeStricter for
// one that does not), its age is far from the max_age boundary on either side,
// and no bound list is empty (such a list matched nothing; a rule cannot say
// so). Roles binding both lists to "*" are included: role validation refused
// them, and a group carrying the converted rule is only warned.
func TestEquivalence_RoleMatcherAndConvertedRule(t *testing.T) {
	b := reviewingBackend(t, nil)
	naming, err := compileFacts("", nil)
	require.NoError(t, err)

	var accepted, refused, wildcards, unions, aged int
	for i, c := range factstest.Frozen[k8sCase](t, "role_equivalence.json") {
		age, err := time.ParseDuration(c.Token.Age)
		require.NoError(t, err)
		token := saToken(c.Token.Namespace, c.Token.Account, c.Token.Audiences, map[string]any{
			"iat": time.Now().Add(-age).Unix(),
		})
		maxAge := maxAgeOf(t, c.Role)

		rule := convertRole(t, "auth/kubernetes/", c.Role, c.MountAudiences)
		got := admitConverted(t, b, token, c.MountAudiences, rule, naming, maxAge)

		require.Equal(t, c.Accepted, got, "case %d: %+v", i, c)
		if c.Accepted {
			accepted++
		} else {
			refused++
		}
		if slices.Contains(c.Role.Names, "*") || slices.Contains(c.Role.Namespaces, "*") {
			wildcards++
		}
		if len(c.MountAudiences) > 1 {
			unions++
		}
		if maxAge > 0 {
			aged++
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

// The documented difference: max_age is stricter once converted. The role
// login let a token whose iat was absent or not a number pass max_age (and ran
// the check once, at login); the converted bound needs a known IssuedAt, so it
// refuses. The case names say what the role login decided.
func TestEquivalence_MaxAgeStricter(t *testing.T) {
	b := reviewingBackend(t, nil)
	naming, err := compileFacts("", nil)
	require.NoError(t, err)
	role := k8sRole{Names: []string{"myapp"}, Namespaces: []string{"default"}, MaxAge: "10m"}
	rule := convertRole(t, "auth/kubernetes/", role, nil)

	cases := []struct {
		name string
		iat  any // nil: no iat claim
		new  bool
	}{
		{"fresh iat: admitted, as by the role login", time.Now().Add(-time.Minute).Unix(), true},
		{"stale iat: refused, as by the role login", time.Now().Add(-time.Hour).Unix(), false},
		{"no iat: refused, where the role login admitted", nil, false},
		{"iat not a number: refused, where the role login admitted", "1700000000", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			extra := map[string]any{}
			if tc.iat != nil {
				extra["iat"] = tc.iat
			}
			token := saToken("default", "myapp", []string{apiServerAudience}, extra)
			assert.Equal(t, tc.new, admitConverted(t, b, token, nil, rule, naming, maxAgeOf(t, role)), "converted")
		})
	}
}
