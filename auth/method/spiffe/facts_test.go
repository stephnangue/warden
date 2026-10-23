package spiffe

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"maps"
	"math/big"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/auth/helper"
	"github.com/stephnangue/warden/auth/helper/factstest"
	spiffelib "github.com/stephnangue/warden/auth/spiffe"
	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/helper/selector"
	"github.com/stephnangue/warden/logical"
)

// =============================================================================
// Fixtures
// =============================================================================

// compileSPIFFEFacts compiles kind and facts as a spiffe mount config does.
func compileSPIFFEFacts(kind string, facts map[string]string) (*logical.MountNaming, error) {
	fc := helper.FactsConfig{EntityKind: kind, Facts: facts}
	fc.CompileFields(spiffeBuiltinFacts())
	return fc.Naming(), fc.Err()
}

func mustNaming(t testing.TB, facts map[string]string) *logical.MountNaming {
	t.Helper()
	n, err := compileSPIFFEFacts("", facts)
	require.NoError(t, err)
	return n
}

// issueSVID issues an X.509-SVID for id with key, signed by ca. Reusing one key
// keeps generated fixtures cheap.
func issueSVID(t testing.TB, ca *x509.Certificate, caKey, key *ecdsa.PrivateKey, id string) *x509.Certificate {
	t.Helper()
	u, err := url.Parse(id)
	require.NoError(t, err)
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	require.NoError(t, err)
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: serial,
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:         []*url.URL{u},
	}, ca, &key.PublicKey, caKey)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// factsFixture is a backend trusting testTD for both SVID kinds, bound to the
// audience "warden".
type factsFixture struct {
	b     *spiffeAuthBackend
	ca    *x509.Certificate
	caKey *ecdsa.PrivateKey
	jwt   *jwtAuthority
}

// newFactsFixture returns a factsFixture, configured with raw over
// bound_audiences "warden".
func newFactsFixture(t *testing.T, raw map[string]any) *factsFixture {
	t.Helper()
	ca, caKey, _ := testCA(t)
	authority := newJWTAuthority(t)
	b, ctx := createTestBackend(t)
	registerTD(t, b, ctx, &spiffelib.TrustDomain{Name: testTD, BundleJSON: combinedBundle(t, testTD, ca, authority)})
	conf := map[string]any{"bound_audiences": []string{"warden"}}
	for k, v := range raw {
		conf[k] = v
	}
	resp := writeConfig(b, conf)
	require.Equal(t, http.StatusOK, resp.StatusCode, "config write: %v", resp.Err)
	return &factsFixture{b: b, ca: ca, caKey: caKey, jwt: authority}
}

func (f *factsFixture) svid(t *testing.T, id string) *x509.Certificate {
	return testSVID(t, f.ca, f.caKey, id)
}

// =============================================================================
// Facts from a verified SVID
// =============================================================================

func TestFacts_FromSVID(t *testing.T) {
	naming := mustNaming(t, map[string]string{"spiffe_id": "workload", "aud": "audiences", "svid": "credential"})
	id := spiffeid.RequireFromString("spiffe://example.org/ns/prod/sa/ci")

	t.Run("x509", func(t *testing.T) {
		adm := newAdmission(id, svidX509, nil, time.Time{}, nil)
		assert.Equal(t, []string{"spiffe://example.org/ns/prod/sa/ci"}, factstest.Values(adm, naming, "spiffe_id"))
		assert.Equal(t, []string{"spiffe://example.org/ns/prod/sa/ci"}, factstest.Values(adm, naming, "workload"))
		assert.Equal(t, []string{"example.org"}, factstest.Values(adm, naming, "trust_domain"))
		assert.Equal(t, []string{"/ns/prod/sa/ci"}, factstest.Values(adm, naming, "path"))
		assert.Equal(t, []string{"x509"}, factstest.Values(adm, naming, "svid"))
		assert.Equal(t, []string{"x509"}, factstest.Values(adm, naming, "credential"))
		assert.Empty(t, factstest.Values(adm, naming, "aud"), "an X.509-SVID carries no audience")
		assert.Empty(t, factstest.Values(adm, naming, "audiences"))
		assert.True(t, adm.IssuedAt.IsZero())
		assert.Equal(t, adm.Facts.(*selector.Table).Bytes(), adm.Bytes)
		assert.Positive(t, adm.Size())
	})

	t.Run("jwt", func(t *testing.T) {
		iat := time.Unix(1_700_000_000, 0)
		auds := []string{"warden", "", "api"}
		adm := newAdmission(id, svidJWT, auds, iat, nil)
		auds[0] = "changed"
		assert.Equal(t, []string{"jwt"}, factstest.Values(adm, naming, "svid"))
		assert.Equal(t, []string{"warden", "api"}, factstest.Values(adm, naming, "aud"), "copied, empty entries left out")
		assert.Equal(t, []string{"warden", "api"}, factstest.Values(adm, naming, "audiences"))
		assert.Equal(t, []string{"spiffe://example.org/ns/prod/sa/ci"}, factstest.Values(adm, naming, "spiffe_id"))
		assert.Equal(t, iat, adm.IssuedAt)
		assert.Equal(t, adm.Facts.(*selector.Table).Bytes(), adm.Bytes)
	})

	t.Run("the ID of a trust domain has no path", func(t *testing.T) {
		adm := newAdmission(spiffeid.RequireFromString("spiffe://example.org"), svidX509, nil, time.Time{}, nil)
		assert.Empty(t, factstest.Values(adm, naming, "path"))
		assert.Equal(t, []string{"spiffe://example.org"}, factstest.Values(adm, naming, "spiffe_id"))
		assert.Equal(t, []string{"example.org"}, factstest.Values(adm, naming, "trust_domain"))
	})

	t.Run("unmapped names are invisible", func(t *testing.T) {
		adm := newAdmission(id, svidJWT, []string{"warden"}, time.Time{}, nil)
		for _, name := range []string{"sub", "iat", "exp", "groups", "/sub"} {
			assert.Empty(t, factstest.Values(adm, naming, name), "fact %q", name)
		}
	})
}

// FactsConfig is flattened into the config's own keys on the way in and on the
// way to storage; bound_audiences is read from a list or a comma-separated
// string.
func TestFactsConfig_JSONFlattened(t *testing.T) {
	cfg, err := mapToSPIFFEAuthConfig(map[string]any{
		"entity_kind":     "human",
		"facts":           map[string]any{"spiffe_id": "workload"},
		"bound_audiences": "warden, api",
	})
	require.NoError(t, err)
	assert.Equal(t, "human", cfg.EntityKind)
	assert.Equal(t, map[string]string{"spiffe_id": "workload"}, cfg.Facts)
	assert.Equal(t, []string{"warden", "api"}, cfg.BoundAudiences)

	cfg, err = mapToSPIFFEAuthConfig(map[string]any{"bound_audiences": []any{"warden"}})
	require.NoError(t, err)
	assert.Equal(t, []string{"warden"}, cfg.BoundAudiences)

	_, err = mapToSPIFFEAuthConfig(map[string]any{"bound_audiences": map[string]any{"a": 1}})
	assert.ErrorContains(t, err, "bound_audiences:")

	raw, err := json.Marshal(normalizedSPIFFEConfig(&SPIFFEAuthConfig{
		TokenTTL:       time.Hour,
		BoundAudiences: []string{"warden"},
		FactsConfig:    helper.FactsConfig{EntityKind: "human", Facts: map[string]string{"spiffe_id": "workload"}},
	}))
	require.NoError(t, err)
	var flat map[string]any
	require.NoError(t, json.Unmarshal(raw, &flat))
	assert.Equal(t, "human", flat["entity_kind"])
	assert.Equal(t, map[string]any{"spiffe_id": "workload"}, flat["facts"])
	assert.Equal(t, []any{"warden"}, flat["bound_audiences"])
	assert.NotContains(t, flat, "FactsConfig")
}

func TestFactNames(t *testing.T) {
	builtins := []string{"aud", "path", "spiffe_id", "svid", "trust_domain"}

	// A mount without a config still admits, so it answers its built-ins as
	// an agent mount.
	unconfigured, _ := createTestBackend(t)
	assert.Nil(t, unconfigured.config)
	assert.Equal(t, builtins, unconfigured.FactNames())
	n := unconfigured.mountFacts.Load()
	require.NotNil(t, n)
	assert.Equal(t, logical.EntityKindAgent, n.Kind)
	assert.Empty(t, n.Mapping.Mapped())

	f := newFactsFixture(t, map[string]any{"facts": map[string]any{"spiffe_id": "workload"}})
	names := f.b.FactNames()
	assert.Equal(t, append(slices.Clone(builtins), "workload"), names)

	// The result is the caller's: changing it leaves the mount's alone.
	names[0] = "changed"
	assert.Equal(t, "aud", f.b.FactNames()[0])

	// The facts field names the sources a spiffe mount has, and no pointers.
	desc := f.b.pathConfig().Fields["facts"].Description
	assert.Contains(t, desc, "one of the SVID fields: "+strings.Join(builtins, ", "))
	assert.NotContains(t, desc, "Pointer")
}

// =============================================================================
// Login carries the admission alongside today's role logic
// =============================================================================

func TestLogin_CarriesAdmission(t *testing.T) {
	f := newFactsFixture(t, map[string]any{"facts": map[string]any{"spiffe_id": "workload", "svid": "credential"}})
	ctx := context.Background()
	const id = "spiffe://" + testTD + "/ns/prod/sa/ci"

	t.Run("x509", func(t *testing.T) {
		svid := f.svid(t, id)
		resp := x509Login(t, f.b, ctx, svid)
		require.Equal(t, http.StatusOK, resp.StatusCode, "login: %v", resp.Err)
		auth := resp.Auth

		// An admission: no policies, no metadata.
		assert.Nil(t, auth.Policies)
		assert.Nil(t, auth.Metadata)
		assert.Equal(t, id, auth.PrincipalID)
		assert.Equal(t, helper.CertFingerprint(svid), auth.ClientToken)

		adm := auth.Admission
		require.NotNil(t, adm)
		assert.Same(t, f.b.mountFacts, adm.Mount, "the admission shares the mount's live naming")
		assert.Empty(t, adm.MountPath, "core names the mount")
		assert.True(t, adm.IssuedAt.IsZero(), "an X.509-SVID has no issue time")
		assert.Equal(t, adm.Facts.(*selector.Table).Bytes(), adm.Bytes)

		n := adm.Mount.Load()
		assert.Equal(t, []string{id}, factstest.Values(adm, n, "workload"))
		assert.Equal(t, []string{"x509"}, factstest.Values(adm, n, "credential"))
		assert.Equal(t, []string{testTD}, factstest.Values(adm, n, "trust_domain"))
		assert.Equal(t, []string{"/ns/prod/sa/ci"}, factstest.Values(adm, n, "path"))
		assert.Empty(t, factstest.Values(adm, n, "aud"))
	})

	t.Run("jwt", func(t *testing.T) {
		before := time.Now().Truncate(time.Second)
		token := f.jwt.sign(t, id, []string{"warden", "other"}, time.Now().Add(time.Hour), map[string]any{
			"groups": []any{"ops"},
			"team":   "platform",
		})
		resp := jwtLogin(t, f.b, ctx, token)
		require.Equal(t, http.StatusOK, resp.StatusCode, "login: %v", resp.Err)
		auth := resp.Auth

		assert.Nil(t, auth.Policies, "a groups claim grants nothing")
		assert.Nil(t, auth.Metadata)
		assert.Equal(t, id, auth.PrincipalID)
		assert.Equal(t, token, auth.ClientToken)

		adm := auth.Admission
		require.NotNil(t, adm)
		assert.Same(t, f.b.mountFacts, adm.Mount)
		assert.False(t, adm.IssuedAt.Before(before), "IssuedAt is the token's iat")
		assert.False(t, adm.IssuedAt.After(time.Now()))
		assert.Equal(t, adm.Facts.(*selector.Table).Bytes(), adm.Bytes)

		n := adm.Mount.Load()
		assert.Equal(t, []string{id}, factstest.Values(adm, n, "workload"))
		assert.Equal(t, []string{"jwt"}, factstest.Values(adm, n, "credential"))
		assert.Equal(t, []string{"warden", "other"}, factstest.Values(adm, n, "aud"), "every audience the token carries")
		assert.Empty(t, factstest.Values(adm, n, "team"), "JWT-SVID claims are not facts")
	})
}

// A refused login carries no admission.
func TestLogin_RefusedCarriesNoAdmission(t *testing.T) {
	f := newFactsFixture(t, nil)
	ctx := context.Background()

	rogue, rogueKey, _ := testCA(t)
	resp := x509Login(t, f.b, ctx, testSVID(t, rogue, rogueKey, "spiffe://"+testTD+"/ns/a/sa/b"))
	require.Error(t, resp.Err)
	assert.Nil(t, resp.Auth)

	token := f.jwt.sign(t, "spiffe://"+testTD+"/ns/a/sa/b", []string{"other"}, time.Now().Add(time.Hour), nil)
	resp = jwtLogin(t, f.b, ctx, token)
	require.Error(t, resp.Err)
	assert.Nil(t, resp.Auth)

	resp = x509Login(t, f.b, ctx, f.svid(t, "spiffe://"+testTD+"/ns/a/sa/b"))
	require.Equal(t, http.StatusOK, resp.StatusCode, "login: %v", resp.Err)
	assert.NotNil(t, resp.Auth.Admission)
}

// =============================================================================
// Metadata equivalence: the mapping renders what metadata_mappings extracts
// =============================================================================

// metadataCase is a SPIFFE ID, a metadata_mappings mapping, and the metadata
// the removed role login rendered from them (Want, frozen).
type metadataCase struct {
	Name    string            `json:"name,omitempty"`
	ID      string            `json:"id"`
	Mapping map[string]string `json:"mapping,omitempty"`
	Want    map[string]string `json:"want,omitempty"`
}

// metadataCases are written by hand; testdata/metadata_equivalence.json holds
// 200 more, generated from a fixed seed: any subset of the ID components, each
// to a distinct name or to itself.
var metadataCases = []metadataCase{
	{Name: "every component", ID: "spiffe://example.org/ns/prod/sa/ci",
		Mapping: map[string]string{"trust_domain": "td", "spiffe_id": "id", "path": "where"},
		Want:    map[string]string{"td": "example.org", "id": "spiffe://example.org/ns/prod/sa/ci", "where": "/ns/prod/sa/ci"}},
	{Name: "identity mappings", ID: "spiffe://example.org/ns/prod/sa/ci",
		Mapping: map[string]string{"spiffe_id": "spiffe_id", "path": "path"},
		Want:    map[string]string{"spiffe_id": "spiffe://example.org/ns/prod/sa/ci", "path": "/ns/prod/sa/ci"}},
	{Name: "no mappings", ID: "spiffe://example.org/ns/prod/sa/ci"},
	{Name: "no path", ID: "spiffe://example.org",
		Mapping: map[string]string{"path": "where", "trust_domain": "td"},
		Want:    map[string]string{"td": "example.org"}},
}

// The mapping renders what the role's metadata_mappings extracted.
func TestRenderMetadata_EquivalentToExtractSPIFFEIDMetadata(t *testing.T) {
	check := func(t *testing.T, c metadataCase) {
		t.Helper()
		id := spiffeid.RequireFromString(c.ID)
		naming := mustNaming(t, c.Mapping)
		// Both SVID kinds render the ID's components alike.
		for _, adm := range []*logical.Admission{
			newAdmission(id, svidX509, nil, time.Time{}, nil),
			newAdmission(id, svidJWT, []string{"warden", "api"}, time.Unix(1_700_000_000, 0), nil),
		} {
			assert.Equal(t, c.Want, adm.RenderMetadata(naming), "case %+v", c)
		}
	}
	for _, c := range metadataCases {
		t.Run(c.Name, func(t *testing.T) { check(t, c) })
	}
	for _, c := range factstest.Frozen[metadataCase](t, "metadata_equivalence.json") {
		check(t, c)
	}
}

// What metadata_mappings could not say: a JWT-SVID's audiences, comma-joined,
// and the SVID kind. An X.509-SVID has no audience to render.
func TestRenderMetadata_AudiencesAndKind(t *testing.T) {
	naming := mustNaming(t, map[string]string{"aud": "audiences", "svid": "credential"})
	id := spiffeid.RequireFromString("spiffe://example.org/sa/api")
	assert.Equal(t, map[string]string{"audiences": "warden,api", "credential": "jwt"},
		newAdmission(id, svidJWT, []string{"warden", "api"}, time.Time{}, nil).RenderMetadata(naming))
	assert.Equal(t, map[string]string{"credential": "x509"},
		newAdmission(id, svidX509, nil, time.Time{}, nil).RenderMetadata(naming))
}

// =============================================================================
// Config: entity_kind, facts and bound_audiences
// =============================================================================

func TestConfigWrite_FactsAndAudiences(t *testing.T) {
	f := newFactsFixture(t, map[string]any{"max_age": 300})
	b := f.b
	ctx := context.Background()

	read := func() map[string]any {
		resp, err := b.handleConfigRead(ctx, &logical.Request{}, &framework.FieldData{})
		require.NoError(t, err)
		return resp.Data
	}
	assert.Equal(t, logical.EntityKindAgent, read()["entity_kind"], "agent by default")
	assert.Empty(t, read()["facts"])
	assert.Equal(t, []string{"warden"}, read()["bound_audiences"], "an agent mount carries its audiences")

	require.Equal(t, http.StatusOK, writeConfig(b, map[string]any{
		"entity_kind":     "human",
		"facts":           map[string]any{"spiffe_id": "workload", "path": "where"},
		"bound_audiences": []string{"warden", "api"},
	}).StatusCode)
	data := read()
	assert.Equal(t, "human", data["entity_kind"])
	assert.Equal(t, map[string]string{"spiffe_id": "workload", "path": "where"}, data["facts"])
	assert.Equal(t, []string{"warden", "api"}, data["bound_audiences"])
	n := b.mountFacts.Load()
	require.NotNil(t, n)
	assert.Equal(t, "human", n.Kind)
	assert.Equal(t, []string{"where", "workload"}, n.Mapping.Mapped())

	// The read is a copy.
	data["facts"].(map[string]string)["spiffe_id"] = "changed"
	data["bound_audiences"].([]string)[0] = "changed"
	assert.Equal(t, "workload", b.config.Facts["spiffe_id"])
	assert.Equal(t, []string{"warden", "api"}, b.config.BoundAudiences)

	// A write that leaves them out keeps them.
	require.Equal(t, http.StatusOK, writeConfig(b, map[string]any{"token_ttl": 600}).StatusCode)
	assert.Equal(t, []string{"where", "workload"}, b.mountFacts.Load().Mapping.Mapped())
	assert.Equal(t, "human", b.mountFacts.Load().Kind)
	assert.Equal(t, []string{"warden", "api"}, b.config.BoundAudiences)
	assert.Equal(t, 5*time.Minute, b.config.MaxAge)

	// The stored config reloads into the same naming and audiences.
	entry, err := b.storageView.Get(ctx, "config")
	require.NoError(t, err)
	var stored map[string]any
	require.NoError(t, entry.DecodeJSON(&stored))
	assert.Equal(t, "human", stored["entity_kind"])
	assert.Equal(t, map[string]any{"spiffe_id": "workload", "path": "where"}, stored["facts"])
	assert.Equal(t, []any{"warden", "api"}, stored["bound_audiences"])
	backend, err := Factory(ctx, &logical.BackendConfig{Logger: testLogger(), StorageView: b.storageView})
	require.NoError(t, err)
	reloaded := backend.(*spiffeAuthBackend)
	require.NoError(t, reloaded.Initialize(ctx))
	t.Cleanup(reloaded.spiffe.Stop)
	assert.Equal(t, b.mountFacts.Load().Kind, reloaded.mountFacts.Load().Kind)
	assert.Equal(t, b.mountFacts.Load().Mapping.Names(), reloaded.mountFacts.Load().Mapping.Names())
	assert.Equal(t, []string{"warden", "api"}, reloaded.config.BoundAudiences)

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
	assert.Len(t, b.FactNames(), len(spiffeBuiltinFacts()))

	// A mount table config may give bound_audiences as a string.
	fromTable, err := Factory(ctx, &logical.BackendConfig{Logger: testLogger(), Config: map[string]any{"bound_audiences": "warden,api"}})
	require.NoError(t, err)
	assert.Equal(t, []string{"warden", "api"}, fromTable.(*spiffeAuthBackend).config.BoundAudiences)
}

// A mount with no config reads back what it runs with: the agent kind and the
// built-in facts it answers, no audiences, default role or max_age, and a
// token_ttl of zero, meaning no cap from the mount, which logins honour.
func TestConfigRead_UnconfiguredRendersDefaults(t *testing.T) {
	b, ctx := createTestBackend(t)
	require.Nil(t, b.config)

	resp, err := b.handleConfigRead(ctx, &logical.Request{}, &framework.FieldData{})
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, map[string]any{
		"token_ttl":       "0s",
		"bound_audiences": []string(nil),
		"max_age":         "0s",
		"entity_kind":     logical.EntityKindAgent,
		"facts":           map[string]string(nil),
	}, resp.Data)
	assert.Equal(t, resp.Data["entity_kind"], b.mountFacts.Load().Kind)
	assert.Equal(t, slices.Sorted(slices.Values(spiffeBuiltinFacts())), b.FactNames(), "it answers the built-ins")

	// No mount cap: the SVID's lifetime applies in full.
	ca, caKey, caPEM := testCA(t)
	registerTD(t, b, ctx, &spiffelib.TrustDomain{Name: testTD, BundlePEM: caPEM})
	svid := testSVID(t, ca, caKey, "spiffe://"+testTD+"/sa/api", func(c *x509.Certificate) {
		c.NotAfter = time.Now().Add(3 * time.Hour)
	})
	login := x509Login(t, b, ctx, svid)
	require.Equal(t, http.StatusOK, login.StatusCode, "login: %v", login.Err)
	assert.Greater(t, login.Auth.TokenTTL, 2*time.Hour+59*time.Minute)
}

// The mount's bound_audiences decide which JWT-SVIDs a login admits; a write
// that would leave an agent mount without them is refused, a human mount may.
func TestConfigWrite_BoundAudiencesDecideLogins(t *testing.T) {
	f := newFactsFixture(t, map[string]any{"bound_audiences": []string{"other"}})
	ctx := context.Background()
	const id = "spiffe://" + testTD + "/ns/a/sa/b"

	resp := jwtLogin(t, f.b, ctx, f.jwt.sign(t, id, []string{"other"}, time.Now().Add(time.Hour), nil))
	require.Equal(t, http.StatusOK, resp.StatusCode, "the mount's audience admits: %v", resp.Err)
	resp = jwtLogin(t, f.b, ctx, f.jwt.sign(t, id, []string{"warden"}, time.Now().Add(time.Hour), nil))
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "another relying party's audience does not")

	before := f.b.config
	resp = writeConfig(f.b, map[string]any{"bound_audiences": ""})
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	require.ErrorIs(t, resp.Err, helper.ErrAgentAudiencesRequired)
	assert.Same(t, before, f.b.config)

	fresh, _ := createTestBackend(t)
	resp = writeConfig(fresh, map[string]any{"token_ttl": "1h"})
	require.Equal(t, http.StatusBadRequest, resp.StatusCode, "an agent mount's first write needs bound_audiences")
	require.ErrorIs(t, resp.Err, helper.ErrAgentAudiencesRequired)
	resp = writeConfig(fresh, map[string]any{"entity_kind": "human"})
	require.Equal(t, http.StatusOK, resp.StatusCode, "a human mount may leave them empty: %v", resp.Err)
}

func TestConfigWrite_FactsAndAudiencesRefused(t *testing.T) {
	cases := []struct {
		name string
		raw  map[string]any
		want string
	}{
		{"bad name", map[string]any{"facts": map[string]any{"spiffe_id": "Workload"}}, "facts:"},
		{"reserved mount", map[string]any{"facts": map[string]any{"spiffe_id": "mount"}}, "reserved"},
		{"reserved kind", map[string]any{"facts": map[string]any{"svid": "kind"}}, "reserved"},
		{"two sources one name", map[string]any{"facts": map[string]any{"spiffe_id": "workload", "path": "workload"}},
			`fact "workload" is produced by both`},
		{"another source onto a built-in", map[string]any{"facts": map[string]any{"path": "aud"}}, "built-in"},
		{"not a field", map[string]any{"facts": map[string]any{"sub": "sub"}}, `source "sub" is not a field of this mount`},
		{"a claim", map[string]any{"facts": map[string]any{"team": "team"}}, `source "team" is not a field of this mount`},
		{"a pointer", map[string]any{"facts": map[string]any{"/act/sub": "actor"}}, "is not a field of this mount"},
		{"non-string name", map[string]any{"facts": map[string]any{"spiffe_id": 5}}, "must be a string"},
		{"unknown entity_kind", map[string]any{"entity_kind": "robot"}, "entity_kind:"},
		{"empty audience in a list", map[string]any{"bound_audiences": []string{"warden", ""}}, "bound_audiences: entry 1 is empty"},
		{"empty audience in a string", map[string]any{"bound_audiences": "warden,,api"}, "bound_audiences: entry 1 is empty"},
		{"blank audience", map[string]any{"bound_audiences": []string{"  "}}, "bound_audiences: entry 0 is empty"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := newFactsFixture(t, map[string]any{
				"facts":           map[string]any{"spiffe_id": "workload"},
				"bound_audiences": []string{"warden"},
			}).b
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
	bad := map[string]any{"facts": map[string]any{"sub": "sub"}, "bound_audiences": []string{"warden"}}

	t.Run("from storage", func(t *testing.T) {
		f := newFactsFixture(t, nil)
		b := f.b
		entry, err := sdklogical.StorageEntryJSON("config", bad)
		require.NoError(t, err)
		require.NoError(t, b.storageView.Put(ctx, entry))

		require.NoError(t, b.Initialize(ctx), "a bad mapping does not fail the load")
		t.Cleanup(b.spiffe.Stop)
		require.NotNil(t, b.config)
		require.Error(t, b.config.FactsConfig.Err())
		assert.Nil(t, b.mountFacts.Load())
		assert.Empty(t, b.FactNames())

		const id = "spiffe://" + testTD + "/ns/a/sa/b"
		for _, resp := range []*logical.Response{
			x509Login(t, b, ctx, f.svid(t, id)),
			jwtLogin(t, b, ctx, f.jwt.sign(t, id, []string{"warden"}, time.Now().Add(time.Hour), nil)),
		} {
			require.Equal(t, http.StatusOK, resp.StatusCode, "logins do not read facts: %v", resp.Err)
			adm := resp.Auth.Admission
			require.NotNil(t, adm)
			adm.MountPath = "auth/spiffe/"
			for _, name := range append(spiffeBuiltinFacts(), "mount", "kind") {
				assert.Empty(t, factstest.Values(adm, adm.Mount.Load(), name), "fact %q", name)
			}
		}

		// A write that leaves the stored facts in place is told how to replace
		// them, and changes nothing.
		before := b.config
		resp := writeConfig(b, map[string]any{"token_ttl": 600})
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
		assert.EqualError(t, resp.Err, `the stored facts do not compile (facts: source "sub" is not a field of this mount (one of aud, path, spiffe_id, svid, trust_domain)); send facts (and entity_kind) in this write to replace them`)
		assert.Same(t, before, b.config)

		// Rewriting the facts restores the naming, for an earlier admission too.
		adm := x509Login(t, b, ctx, f.svid(t, id)).Auth.Admission
		require.Equal(t, http.StatusOK, writeConfig(b, map[string]any{"facts": map[string]any{}}).StatusCode)
		assert.Equal(t, []string{id}, factstest.Values(adm, adm.Mount.Load(), "spiffe_id"))
	})

	t.Run("from the mount table", func(t *testing.T) {
		backend, err := Factory(ctx, &logical.BackendConfig{Logger: testLogger(), Config: bad})
		require.NoError(t, err, "a bad mapping does not fail the mount")
		b := backend.(*spiffeAuthBackend)
		require.Error(t, b.config.FactsConfig.Err())
		assert.Nil(t, b.mountFacts.Load())
	})
}

// The naming is published with the config it was compiled from, in one
// critical section: a reader holding configMu sees them agree, a lock-free
// reader sees one published naming whole, and logins racing config writes all
// share the mount's MountFacts.
func TestNaming_PublishNeverHalfApplied(t *testing.T) {
	f := newFactsFixture(t, nil)
	b := f.b
	ctx := context.Background()
	svid := f.svid(t, "spiffe://"+testTD+"/ns/a/sa/b")
	writes := []map[string]any{
		{"entity_kind": "agent", "facts": map[string]any{"spiffe_id": "workload"}},
		{"entity_kind": "human", "facts": map[string]any{"path": "where", "svid": "credential"}},
	}
	whole := func(n *logical.MountNaming) bool {
		switch n.Kind {
		case logical.EntityKindAgent:
			return slices.Equal(n.Mapping.Mapped(), []string{"workload"})
		case logical.EntityKindHuman:
			return slices.Equal(n.Mapping.Mapped(), []string{"credential", "where"})
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

	builtins := len(spiffeBuiltinFacts())
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
			req := &logical.Request{HTTPRequest: newSVIDHTTPRequest(t, svid)}
			d := &framework.FieldData{Raw: map[string]any{"role": "api"}, Schema: b.pathLogin().Fields}
			for !stop.Load() {
				resp, err := b.handleLogin(ctx, req, d)
				if err != nil || resp.StatusCode != http.StatusOK || resp.Auth == nil || resp.Auth.Admission == nil {
					report("login failed: %v %+v", err, resp)
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
				if n.Kind == logical.EntityKindHuman && len(factstest.Values(adm, n, "credential")) != 1 {
					report("human naming lost credential")
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
// Equivalence: the removed role matcher (frozen) and the role converted to
// selector rules
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

// convertIDPattern converts an allowed_spiffe_ids pattern (segment wildcards)
// to a selector value, as allowed_uri_sans converts on a cert mount: '+'
// becomes '*', a trailing '/*' becomes '/**' and 'scheme://*' becomes
// 'scheme://**'; every other segment and the scheme are written exactly. A
// pattern without a scheme matches no SPIFFE ID today (every ID has one), so
// it converts to nothing: live is false and the pattern is dropped.
func convertIDPattern(p string) (v string, live bool, err error) {
	if err := factstest.SegmentPatternError(p); err != nil {
		return "", false, err
	}
	scheme, body, ok := strings.Cut(p, "://")
	if !ok {
		return "", false, nil
	}
	if body == "*" {
		return escapeValue(scheme) + "://**", true, nil
	}
	segs := strings.Split(body, "/")
	for i, s := range segs {
		switch {
		case s == "+":
			segs[i] = "*"
		case s == "*" && i == len(segs)-1:
			segs[i] = "**"
		default:
			segs[i] = escapeValue(s)
		}
	}
	return escapeValue(scheme) + "://" + strings.Join(segs, "/"), true, nil
}

// convertRole converts one spiffe role to selector rules, pinned to the mount,
// any one of which admits. Every rule holds the role's trust domain (by name;
// a role may give it as spiffe://<name>) and, when it has allowed_spiffe_ids,
// their converted patterns. An X.509-SVID was admitted whatever the role's
// audiences, so it has a rule of its own on svid; a JWT-SVID only when the role
// had bound_audiences, which become the second rule's aud (the mount's
// bound_audiences hold every role's). A role whose patterns all convert to
// nothing admitted nothing, and converts to no rule.
func convertRole(t testing.TB, mountPath string, role spiffeRole, convert func(string) (string, bool, error)) ([]*selector.Rule, error) {
	t.Helper()
	td, err := spiffeid.TrustDomainFromString(role.TrustDomain)
	if err != nil {
		return nil, err
	}
	base := map[string][]string{"mount": {mountPath}, factTrustDomain: {escapeValue(td.Name())}}
	if len(role.AllowedIDs) > 0 {
		var ids []string
		for _, p := range role.AllowedIDs {
			v, live, err := convert(p)
			if err != nil {
				return nil, err
			}
			if live {
				ids = append(ids, v)
			}
		}
		if len(ids) == 0 {
			return nil, nil
		}
		base[factSPIFFEID] = ids
	}
	compile := func(extra map[string][]string) *selector.Rule {
		rule := maps.Clone(base)
		maps.Copy(rule, extra)
		compiled, err := selector.Compile(rule)
		require.NoError(t, err, "rule %v", rule)
		return compiled
	}
	rules := []*selector.Rule{compile(map[string][]string{factSVID: {svidX509}})}
	if len(role.BoundAudiences) > 0 {
		auds := make([]string, len(role.BoundAudiences))
		for i, a := range role.BoundAudiences {
			auds[i] = escapeValue(a)
		}
		rules = append(rules, compile(map[string][]string{factSVID: {svidJWT}, factAudiences: auds}))
	}
	return rules, nil
}

// admitConverted runs the converted model for one credential (cert, or else
// token): verification alone (no role binding) against set, a JWT-SVID against
// the mount's bound_audiences, the admission built as a login builds it, and
// the rules matched through the naming, any one of them.
func admitConverted(set *spiffebundle.Set, cert *x509.Certificate, token string, mountAuds []string, rules []*selector.Rule, naming *logical.MountNaming) bool {
	if len(rules) == 0 {
		return false
	}
	var adm *logical.Admission
	if cert != nil {
		id, _, err := spiffelib.VerifyX509SVIDChain(set, []*x509.Certificate{cert})
		if err != nil {
			return false
		}
		adm = newAdmission(id, svidX509, nil, time.Time{}, nil)
	} else {
		svid, err := spiffelib.VerifyJWTSVIDToken(set, token, mountAuds)
		if err != nil {
			return false
		}
		adm = newAdmission(svid.ID, svidJWT, svid.Audience, helper.IssuedAt(svid.Claims), nil)
	}
	adm.MountPath = "auth/spiffe/"
	src := factstest.Source{Adm: adm, Naming: naming}
	return slices.ContainsFunc(rules, func(r *selector.Rule) bool { return r.Match(src) })
}

// equivalenceRun is what one run of the generator saw.
type equivalenceRun struct {
	mismatches        []string
	accepted, refused map[string]int // by SVID kind
	patterns          int            // roles with allowed_spiffe_ids
	deadPatterns      int            // scheme-less patterns, which match no ID
	audienceRoles     int            // roles with bound_audiences
	x509OnlyRefused   int            // JWT-SVIDs the mount verified, refused by a role without audiences
	idFormTrustDomain int            // roles giving trust_domain as spiffe://<name>
}

// spiffeRole is what a removed spiffe auth role bound an SVID to.
type spiffeRole struct {
	TrustDomain    string   `json:"trust_domain"`
	AllowedIDs     []string `json:"allowed_spiffe_ids,omitempty"`
	BoundAudiences []string `json:"bound_audiences,omitempty"`
}

// spiffeCase is one frozen sample of the removed role login: an SVID of either
// kind for ID (an X.509-SVID, or a JWT-SVID carrying Audiences, expired when
// Expired), signed by its trust domain's authority or, when Rogue, by one no
// trust domain holds; the role it was presented for; the converted mount's
// bound_audiences (every role's, plus others); and whether the role login
// accepted it.
type spiffeCase struct {
	Kind           string     `json:"svid"`
	ID             string     `json:"id"`
	Rogue          bool       `json:"rogue,omitempty"`
	Audiences      []string   `json:"aud,omitempty"`
	Expired        bool       `json:"expired,omitempty"`
	Role           spiffeRole `json:"role"`
	MountAudiences []string   `json:"mount_audiences,omitempty"`
	Accepted       bool       `json:"accepted"`
}

// equivalenceCases are the frozen cases in testdata/role_equivalence.json,
// generated (2000, from a fixed seed) over trust domains a, b and c.example.org.
// Half the patterns, trust domains and audiences were made from the
// credential, so enough roles accept it for agreement to mean something.
func equivalenceCases(t *testing.T) []spiffeCase {
	return factstest.Frozen[spiffeCase](t, "role_equivalence.json")
}

// runEquivalence compares, over cases, the removed role login's decision
// (Accepted: the SVID verified against the trust bundles, its ID in the role's
// trust domain and matching one of its allowed_spiffe_ids when it had any, a
// JWT-SVID only for a role with bound_audiences, against them) with the
// converted model's (admitConverted over convertRole, with convert for
// allowed_spiffe_ids).
//
// Trust domains a and b are loaded with both X.509 and JWT authorities; c is
// not loaded, and a rogue CA and JWT key sign the cases marked rogue.
func runEquivalence(t *testing.T, cases []spiffeCase, convert func(string) (string, bool, error)) equivalenceRun {
	t.Helper()
	ctx := context.Background()
	b, _ := createTestBackend(t)
	naming := mustNaming(t, nil)

	tds := []string{"a.example.org", "b.example.org", "c.example.org"}
	cas := map[string]*x509.Certificate{}
	caKeys := map[string]*ecdsa.PrivateKey{}
	jwts := map[string]*jwtAuthority{}
	for _, td := range tds {
		cas[td], caKeys[td], _ = testCA(t)
		jwts[td] = newJWTAuthority(t)
	}
	for _, td := range tds[:2] {
		require.NoError(t, b.spiffe.SetTrustDomain(ctx, &spiffelib.TrustDomain{Name: td, BundleJSON: combinedBundle(t, td, cas[td], jwts[td])}))
	}
	require.NoError(t, b.spiffe.RebuildBundleSet(ctx))
	set := b.spiffe.SnapshotBundleSet()
	rogueCA, rogueKey, _ := testCA(t)
	rogueJWT := newJWTAuthority(t)
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	run := equivalenceRun{accepted: map[string]int{}, refused: map[string]int{}}
	for i, c := range cases {
		td := spiffeid.RequireFromString(c.ID).TrustDomain().Name()
		if strings.HasPrefix(c.Role.TrustDomain, "spiffe://") {
			run.idFormTrustDomain++
		}
		if len(c.Role.AllowedIDs) > 0 {
			run.patterns++
		}
		for _, p := range c.Role.AllowedIDs {
			if !strings.Contains(p, "://") {
				run.deadPatterns++
			}
		}
		if len(c.Role.BoundAudiences) > 0 {
			run.audienceRoles++
		}

		// The credential.
		var cert *x509.Certificate
		var token string
		switch c.Kind {
		case svidX509:
			ca, caKey := cas[td], caKeys[td]
			if c.Rogue {
				ca, caKey = rogueCA, rogueKey
			}
			cert = issueSVID(t, ca, caKey, leafKey, c.ID)
		case svidJWT:
			exp := time.Now().Add(time.Hour)
			if c.Expired {
				exp = time.Now().Add(-time.Hour)
			}
			signer := jwts[td]
			if c.Rogue {
				signer = rogueJWT
			}
			token = signer.sign(t, c.ID, c.Audiences, exp, nil)
		default:
			t.Fatalf("case %d: SVID kind %q", i, c.Kind)
		}

		rules, err := convertRole(t, "auth/spiffe/", c.Role, convert)
		require.NoError(t, err, "case %d: role %+v", i, c.Role)
		got := admitConverted(set, cert, token, c.MountAudiences, rules, naming)

		if c.Kind == svidJWT && len(c.Role.BoundAudiences) == 0 {
			if _, err := spiffelib.VerifyJWTSVIDToken(set, token, c.MountAudiences); err == nil {
				run.x509OnlyRefused++
			}
		}
		if c.Accepted != got {
			run.mismatches = append(run.mismatches, fmt.Sprintf("case %d: %+v: converted %v", i, c, got))
			continue
		}
		if c.Accepted {
			run.accepted[c.Kind]++
		} else {
			run.refused[c.Kind]++
		}
	}
	return run
}

// TestEquivalence_RoleMatcherAndConvertedRules checks, over the frozen SVIDs
// of both kinds, roles and mount audiences, that the converted model accepts
// an SVID exactly when the removed role login did: the conversion is exact.
func TestEquivalence_RoleMatcherAndConvertedRules(t *testing.T) {
	run := runEquivalence(t, equivalenceCases(t), convertIDPattern)
	for _, m := range run.mismatches {
		t.Error(m)
	}
	// Both outcomes and every feature are exercised, so agreement is not vacuous.
	t.Logf("accepted %v, refused %v, roles with patterns %d (dead patterns %d), with audiences %d, x509-only roles refusing a verified JWT-SVID %d, spiffe:// trust domains %d",
		run.accepted, run.refused, run.patterns, run.deadPatterns, run.audienceRoles, run.x509OnlyRefused, run.idFormTrustDomain)
	for _, kind := range []string{svidX509, svidJWT} {
		assert.Greater(t, run.accepted[kind], 30, "accepted %s", kind)
		assert.Greater(t, run.refused[kind], 30, "refused %s", kind)
	}
	assert.Greater(t, run.patterns, 30)
	assert.Greater(t, run.deadPatterns, 0)
	assert.Greater(t, run.audienceRoles, 30)
	assert.Greater(t, run.x509OnlyRefused, 0)
	assert.Greater(t, run.idFormTrustDomain, 30)
}

// The frozen cases catch a conversion that skips a step: each mutation below
// leaves one rewrite out, and the comparison must then disagree somewhere in
// the first 600 cases.
func TestEquivalence_CatchesBrokenConversion(t *testing.T) {
	cases := equivalenceCases(t)[:600]
	mutations := map[string]func(string) (string, bool, error){
		// A trailing '/*' kept as '/*' no longer crosses '/'.
		"trailing star kept": func(p string) (string, bool, error) {
			v, live, err := convertIDPattern(p)
			if strings.HasSuffix(v, "/**") && !strings.HasSuffix(p, "://*") {
				v = strings.TrimSuffix(v, "*")
			}
			return v, live, err
		},
		// '+' written as a literal matches only a segment named '+'.
		"plus kept": func(p string) (string, bool, error) {
			v, live, err := convertIDPattern(strings.ReplaceAll(p, "+", "plus"))
			return strings.ReplaceAll(v, "plus", "+"), live, err
		},
	}
	for name, convert := range mutations {
		t.Run(name, func(t *testing.T) {
			run := runEquivalence(t, cases, convert)
			assert.NotEmpty(t, run.mismatches, "a broken conversion must be caught")
		})
	}
}

// A role without bound_audiences admitted no JWT-SVID (the role login refused
// the token below and accepted the certificate), so it converts to an
// X.509-only rule: once the mount's bound_audiences admit the token, its
// "svid" is what keeps the role from accepting it.
func TestEquivalence_RoleWithoutAudiencesIsX509Only(t *testing.T) {
	f := newFactsFixture(t, nil)
	set := f.b.spiffe.SnapshotBundleSet()
	naming := mustNaming(t, nil)
	rules, err := convertRole(t, "auth/spiffe/", spiffeRole{TrustDomain: testTD}, convertIDPattern)
	require.NoError(t, err)
	require.Len(t, rules, 1)

	const id = "spiffe://" + testTD + "/sa/api"
	token := f.jwt.sign(t, id, []string{"warden"}, time.Now().Add(time.Hour), nil)
	assert.False(t, admitConverted(set, nil, token, []string{"warden"}, rules, naming), "converted")

	cert := f.svid(t, id)
	assert.True(t, admitConverted(set, cert, "", []string{"warden"}, rules, naming))
}

func TestConvertIDPattern(t *testing.T) {
	cases := map[string]string{
		"spiffe://*":                     "spiffe://**",
		"spiffe://+/ns/*":                "spiffe://*/ns/**",
		"spiffe://example.org/ns/+/sa/+": "spiffe://example.org/ns/*/sa/*",
		"spiffe://example.org":           "spiffe://example.org",
		"spiffe://example.org/a*b":       `spiffe://example.org/a\*b`,
		"https://+/x?y/+":                `https://*/x\?y/*`,
	}
	for in, want := range cases {
		got, live, err := convertIDPattern(in)
		require.NoError(t, err, in)
		assert.True(t, live, in)
		assert.Equal(t, want, got, in)
	}

	// A pattern without a scheme matched no SPIFFE ID in the role login (an ID
	// always has one), and converts to nothing.
	for _, p := range []string{"example.org/+", "*", "+/ns/*"} {
		_, live, err := convertIDPattern(p)
		require.NoError(t, err, p)
		assert.False(t, live, p)
	}

	// Patterns role writes refused are refused.
	for _, p := range []string{"spiffe://+*", "spiffe://a//b", "spiffe://*/a"} {
		_, _, err := convertIDPattern(p)
		assert.Error(t, err, "pattern %q was refused on role writes", p)
	}

	// A role left with no live pattern admitted nothing.
	rules, err := convertRole(t, "auth/spiffe/", spiffeRole{TrustDomain: "example.org", AllowedIDs: []string{"example.org/*"}}, convertIDPattern)
	require.NoError(t, err)
	assert.Nil(t, rules)
}
