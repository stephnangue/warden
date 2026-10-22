package cert

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	mrand "math/rand"
	"net/http"
	"net/url"
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
	"github.com/stephnangue/warden/helper/selector"
	"github.com/stephnangue/warden/logical"
)

// =============================================================================
// Fixtures
// =============================================================================

// authority is a CA for fixtures: its certificate, key and PEM.
type authority struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  string
}

// fixtureSerial numbers fixture certificates, so two certificates for the same
// subject and key still differ.
var fixtureSerial atomic.Int64

func newFixtureKey(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key
}

// issueCA issues a CA certificate named cn for key: self-signed when parent is
// nil, otherwise signed by parent (an intermediate, or a cross-certificate when
// cn and key are another CA's). The subject key id derives from key, so two
// CAs sharing a key and name can each issue for the other's subjects.
func issueCA(t testing.TB, cn string, key *ecdsa.PrivateKey, parent *authority) *authority {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(fixtureSerial.Add(1)),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	issuer, signer := tmpl, key
	if parent != nil {
		issuer, signer = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, issuer, &key.PublicKey, signer)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return &authority{
		cert: cert,
		key:  key,
		pem:  string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
	}
}

// issueLeaf issues a client certificate for key, signed by parent, with the
// template fields mutate sets.
func issueLeaf(t testing.TB, parent *authority, key *ecdsa.PrivateKey, mutate func(*x509.Certificate)) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(fixtureSerial.Add(1)),
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if mutate != nil {
		mutate(tmpl)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent.cert, &key.PublicKey, parent.key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

func mustURL(t testing.TB, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	require.NoError(t, err)
	return u
}

// fingerprint is the "ca" value of an anchor: lowercase hex SHA-256 of its DER.
func fingerprint(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return hex.EncodeToString(sum[:])
}

// sortedFingerprints returns the "ca" values of as, in the order "ca" holds
// them: sorted.
func sortedFingerprints(as ...*authority) []string {
	out := make([]string, len(as))
	for i, a := range as {
		out[i] = fingerprint(a.cert)
	}
	slices.Sort(out)
	return out
}

// verifyChains verifies leaf as login does, against roots, with intermediates
// when given.
func verifyChains(t testing.TB, leaf *x509.Certificate, roots []*authority, intermediates []*authority) [][]*x509.Certificate {
	t.Helper()
	opts := x509.VerifyOptions{
		Roots:     x509.NewCertPool(),
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	for _, r := range roots {
		opts.Roots.AddCert(r.cert)
	}
	if len(intermediates) > 0 {
		opts.Intermediates = x509.NewCertPool()
		for _, i := range intermediates {
			opts.Intermediates.AddCert(i.cert)
		}
	}
	chains, err := leaf.Verify(opts)
	require.NoError(t, err)
	return chains
}

// compileCertFacts compiles kind and facts as a cert mount config does.
func compileCertFacts(kind string, facts map[string]string) (*logical.MountNaming, error) {
	fc := helper.FactsConfig{EntityKind: kind, Facts: facts}
	fc.CompileFields(certBuiltinFacts())
	return fc.Naming(), fc.Err()
}

// certLogin logs in with cert.
func certLogin(t *testing.T, b *certAuthBackend, cert *x509.Certificate) *logical.Response {
	t.Helper()
	resp, err := b.handleLogin(context.Background(),
		&logical.Request{HTTPRequest: newCertHTTPRequest(t, cert)},
		&framework.FieldData{Raw: map[string]any{}, Schema: b.pathLogin().Fields})
	require.NoError(t, err)
	return resp
}

// factsBackend returns a backend with storage, configured to trust ca plus
// extra config keys.
func factsBackend(t *testing.T, ca *authority, extra map[string]any) *certAuthBackend {
	t.Helper()
	b, _ := createTestBackend(t)
	raw := map[string]any{"trusted_ca_pem": ca.pem}
	for k, v := range extra {
		raw[k] = v
	}
	resp := writeConfig(b, raw)
	require.Equal(t, http.StatusOK, resp.StatusCode, "config write: %v", resp.Err)
	return b
}

// =============================================================================
// Facts from a verified certificate
// =============================================================================

func TestFacts_FromCertificate(t *testing.T) {
	naming, err := compileCertFacts("", map[string]string{
		"cn":      "workload",
		"uri_san": "uri",
		"ou":      "ou",
	})
	require.NoError(t, err)

	root := issueCA(t, "Root", newFixtureKey(t), nil)
	leaf := issueLeaf(t, root, newFixtureKey(t), func(c *x509.Certificate) {
		c.SerialNumber = big.NewInt(0).SetBytes([]byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x10})
		c.Subject = pkix.Name{
			CommonName:         "agent-1",
			OrganizationalUnit: []string{"eng", "platform"},
			Organization:       []string{"Acme"},
		}
		c.DNSNames = []string{"agent-1.example.com", "agent.example.com"}
		c.EmailAddresses = []string{"agent@example.com"}
		c.URIs = []*url.URL{mustURL(t, "spiffe://example.com/ns/ci/sa/agent"), mustURL(t, "https://agent.example.com/x")}
	})
	adm := newAdmission(leaf, verifyChains(t, leaf, []*authority{root}, nil), nil)

	serial := leaf.SerialNumber.String()
	cases := []struct {
		name string
		want []string
	}{
		{"cn", []string{"agent-1"}},
		{"serial", []string{serial}},
		{"ou", []string{"eng", "platform"}},
		{"org", []string{"Acme"}},
		{"dns_san", []string{"agent-1.example.com", "agent.example.com"}},
		{"email_san", []string{"agent@example.com"}},
		{"uri_san", []string{"spiffe://example.com/ns/ci/sa/agent", "https://agent.example.com/x"}},
		{"ca", []string{fingerprint(root.cert)}},
		{"workload", []string{"agent-1"}},
		{"uri", []string{"spiffe://example.com/ns/ci/sa/agent", "https://agent.example.com/x"}},
		{"kind", []string{logical.EntityKindAgent}},
		{"mount", nil}, // set by core at LoginCreateToken
		{"issuer", nil},
		{"iat", nil},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, factstest.Values(adm, naming, tc.name), "fact %q", tc.name)
	}
	assert.Equal(t, "20988295479420645136", serial, "the serial renders in decimal")
	assert.Regexp(t, "^[0-9a-f]{64}$", factstest.Values(adm, naming, "ca")[0])

	assert.Equal(t, map[string]string{
		"workload": "agent-1",
		"uri":      "spiffe://example.com/ns/ci/sa/agent,https://agent.example.com/x",
		"ou":       "eng,platform",
	}, adm.RenderMetadata(naming))

	assert.True(t, adm.IssuedAt.IsZero(), "a certificate has no issue time")
	assert.Nil(t, adm.Mount)
	assert.Empty(t, adm.MountPath)
	want := 0
	for _, tc := range cases[:8] {
		want += len(tc.name)
		for _, v := range tc.want {
			want += len(v)
		}
	}
	assert.Equal(t, int64(want), adm.Bytes)
	assert.Equal(t, int64(want), adm.Size())
}

// An empty value is not a fact: a certificate without a common name has no
// "cn", and empty subject entries are left out.
func TestFacts_EmptyValues(t *testing.T) {
	naming, err := compileCertFacts("", nil)
	require.NoError(t, err)
	root := issueCA(t, "Root", newFixtureKey(t), nil)
	leaf := issueLeaf(t, root, newFixtureKey(t), func(c *x509.Certificate) {
		c.Subject = pkix.Name{OrganizationalUnit: []string{"", "eng"}, Organization: []string{""}}
	})
	require.Equal(t, []string{"", "eng"}, leaf.Subject.OrganizationalUnit, "the empty entry survives encoding")

	adm := newAdmission(leaf, nil, nil)
	for _, name := range []string{"cn", "org", "dns_san", "email_san", "uri_san", "ca"} {
		assert.Empty(t, factstest.Values(adm, naming, name), "fact %q", name)
	}
	assert.Equal(t, []string{"eng"}, factstest.Values(adm, naming, "ou"))
	assert.Equal(t, []string{leaf.SerialNumber.String()}, factstest.Values(adm, naming, "serial"))

	// No chains at all, and a certificate without a serial.
	adm = newAdmission(&x509.Certificate{}, nil, nil)
	assert.Empty(t, factstest.Values(adm, naming, "ca"))
	assert.Empty(t, factstest.Values(adm, naming, "serial"))
}

// "ca" holds the anchor of every verified chain, each distinct anchor once.
func TestFacts_CAOncePerDistinctAnchor(t *testing.T) {
	naming, err := compileCertFacts("", nil)
	require.NoError(t, err)

	t.Run("two chains to two roots", func(t *testing.T) {
		// A root and its cross-certificate from another root: same name and
		// key, different certificates. With both trusted, the leaf verifies
		// to each.
		rootKey := newFixtureKey(t)
		root := issueCA(t, "Root", rootKey, nil)
		other := issueCA(t, "Other Root", newFixtureKey(t), nil)
		cross := issueCA(t, "Root", rootKey, other)
		leaf := issueLeaf(t, root, newFixtureKey(t), func(c *x509.Certificate) { c.Subject.CommonName = "agent-1" })

		chains := verifyChains(t, leaf, []*authority{root, cross}, nil)
		require.Len(t, chains, 2)
		adm := newAdmission(leaf, chains, nil)
		assert.Equal(t, sortedFingerprints(root, cross), factstest.Values(adm, naming, "ca"))

		// The same anchors in the same order, whatever order the chains came in.
		slices.Reverse(chains)
		assert.Equal(t, sortedFingerprints(root, cross), factstest.Values(newAdmission(leaf, chains, nil), naming, "ca"))

		// The classic cross-signed shape: the cross-certificate as an
		// intermediate to the other root.
		chains = verifyChains(t, leaf, []*authority{root, other}, []*authority{cross})
		require.Len(t, chains, 2)
		adm = newAdmission(leaf, chains, nil)
		assert.Equal(t, sortedFingerprints(root, other), factstest.Values(adm, naming, "ca"))
	})

	t.Run("two chains to one root", func(t *testing.T) {
		// Two intermediates with the same name and key under one root: two
		// chains, one anchor.
		root := issueCA(t, "Root", newFixtureKey(t), nil)
		interKey := newFixtureKey(t)
		inter1 := issueCA(t, "Intermediate", interKey, root)
		inter2 := issueCA(t, "Intermediate", interKey, root)
		leaf := issueLeaf(t, inter1, newFixtureKey(t), func(c *x509.Certificate) { c.Subject.CommonName = "agent-1" })

		chains := verifyChains(t, leaf, []*authority{root}, []*authority{inter1, inter2})
		require.Len(t, chains, 2)
		require.NotEqual(t, chains[0][1].Raw, chains[1][1].Raw)
		adm := newAdmission(leaf, chains, nil)
		assert.Equal(t, []string{fingerprint(root.cert)}, factstest.Values(adm, naming, "ca"))
		assert.Equal(t, map[string]string{"anchor": fingerprint(root.cert)}, adm.RenderMetadata(mustNaming(t, map[string]string{"ca": "anchor"})))
	})
}

func mustNaming(t testing.TB, facts map[string]string) *logical.MountNaming {
	t.Helper()
	n, err := compileCertFacts("", facts)
	require.NoError(t, err)
	return n
}

// FactsConfig is flattened into the config's own keys on the way in and on the
// way to storage.
func TestFactsConfig_JSONFlattened(t *testing.T) {
	cfg, err := mapToCertAuthConfig(map[string]any{
		"principal_claim": "cn",
		"entity_kind":     "human",
		"facts":           map[string]any{"cn": "workload"},
	})
	require.NoError(t, err)
	assert.Equal(t, "human", cfg.EntityKind)
	assert.Equal(t, map[string]string{"cn": "workload"}, cfg.Facts)

	raw, err := json.Marshal(normalizedCertConfig(&CertAuthConfig{
		PrincipalClaim: "cn",
		FactsConfig:    helper.FactsConfig{EntityKind: "human", Facts: map[string]string{"cn": "workload"}},
	}))
	require.NoError(t, err)
	var flat map[string]any
	require.NoError(t, json.Unmarshal(raw, &flat))
	assert.Equal(t, "human", flat["entity_kind"])
	assert.Equal(t, map[string]any{"cn": "workload"}, flat["facts"])
	assert.NotContains(t, flat, "FactsConfig")
}

func TestFactNames(t *testing.T) {
	root := issueCA(t, "Root", newFixtureKey(t), nil)
	b := factsBackend(t, root, nil)
	builtins := []string{"ca", "cn", "dns_san", "email_san", "org", "ou", "serial", "uri_san"}
	assert.Equal(t, builtins, b.FactNames())

	require.Equal(t, http.StatusOK, writeConfig(b, map[string]any{
		"facts": map[string]any{"cn": "workload"},
	}).StatusCode)
	names := b.FactNames()
	assert.Equal(t, append(slices.Clone(builtins), "workload"), names)

	// The result is the caller's: changing it leaves the mount's alone.
	names[0] = "changed"
	assert.Equal(t, "ca", b.FactNames()[0])

	unconfigured, _ := createTestBackend(t)
	assert.Empty(t, unconfigured.FactNames())

	// The facts field names the sources a cert mount has, and no pointers.
	desc := b.pathConfig().Fields["facts"].Description
	assert.Contains(t, desc, "one of the certificate fields: "+strings.Join(builtins, ", "))
	assert.NotContains(t, desc, "Pointer")
}

// =============================================================================
// Login is an admission
// =============================================================================

func TestLogin_CarriesAdmission(t *testing.T) {
	root := issueCA(t, "Root", newFixtureKey(t), nil)
	b := factsBackend(t, root, map[string]any{"facts": map[string]any{"cn": "workload", "ca": "anchor"}})
	leaf := issueLeaf(t, root, newFixtureKey(t), func(c *x509.Certificate) {
		c.Subject.CommonName = "agent-1"
		c.DNSNames = []string{"a.example.com", "b.example.com"}
	})

	resp := certLogin(t, b, leaf)
	require.Equal(t, http.StatusOK, resp.StatusCode, "login: %v", resp.Err)
	auth := resp.Auth
	require.NotNil(t, auth)

	// An admission: no policies, no metadata.
	assert.Nil(t, auth.Policies)
	assert.Nil(t, auth.Metadata)
	assert.Equal(t, "cert_role", auth.TokenType)
	assert.Equal(t, "agent-1", auth.PrincipalID)
	assert.Equal(t, certFingerprint(leaf), auth.ClientToken)

	adm := auth.Admission
	require.NotNil(t, adm)
	assert.Same(t, b.mountFacts, adm.Mount, "the admission shares the mount's live naming")
	assert.Empty(t, adm.MountPath, "core names the mount")
	assert.True(t, adm.IssuedAt.IsZero())
	assert.Equal(t, adm.Facts.(*selector.Table).Bytes(), adm.Bytes)
	assert.Positive(t, adm.Size())

	n := adm.Mount.Load()
	assert.Equal(t, []string{"agent-1"}, factstest.Values(adm, n, "workload"))
	assert.Equal(t, []string{"a.example.com", "b.example.com"}, factstest.Values(adm, n, "dns_san"))
	assert.Equal(t, []string{fingerprint(root.cert)}, factstest.Values(adm, n, "ca"))
	assert.Equal(t, []string{fingerprint(root.cert)}, factstest.Values(adm, n, "anchor"))
}

// The anchors are those of the chains login verified against the mount's pool:
// every trusted root the certificate reaches.
func TestLogin_AdmissionAnchors(t *testing.T) {
	rootKey := newFixtureKey(t)
	root := issueCA(t, "Root", rootKey, nil)
	other := issueCA(t, "Other Root", newFixtureKey(t), nil)
	cross := issueCA(t, "Root", rootKey, other)
	leaf := issueLeaf(t, root, newFixtureKey(t), func(c *x509.Certificate) { c.Subject.CommonName = "agent-1" })

	// Both the root and its cross-certificate trusted: two anchors.
	b := factsBackend(t, &authority{pem: root.pem + cross.pem}, nil)
	resp := certLogin(t, b, leaf)
	require.Equal(t, http.StatusOK, resp.StatusCode, "login: %v", resp.Err)
	adm := resp.Auth.Admission
	assert.Equal(t, sortedFingerprints(root, cross), factstest.Values(adm, adm.Mount.Load(), "ca"))

	// Only the cross-certificate trusted: its anchor alone.
	b = factsBackend(t, &authority{pem: cross.pem}, nil)
	resp = certLogin(t, b, leaf)
	require.Equal(t, http.StatusOK, resp.StatusCode, "login: %v", resp.Err)
	adm = resp.Auth.Admission
	assert.Equal(t, []string{fingerprint(cross.cert)}, factstest.Values(adm, adm.Mount.Load(), "ca"))
}

// A refused login carries no admission.
func TestLogin_RefusedCarriesNoAdmission(t *testing.T) {
	root := issueCA(t, "Root", newFixtureKey(t), nil)
	untrusted := issueCA(t, "Untrusted", newFixtureKey(t), nil)
	b := factsBackend(t, root, nil)
	key := newFixtureKey(t)
	for _, leaf := range []*x509.Certificate{
		issueLeaf(t, untrusted, key, func(c *x509.Certificate) { c.Subject.CommonName = "agent-1" }), // chain
		issueLeaf(t, root, key, func(c *x509.Certificate) { c.Subject.CommonName = "" }),             // no principal
	} {
		resp := certLogin(t, b, leaf)
		require.Error(t, resp.Err)
		assert.Nil(t, resp.Auth)
	}
	resp := certLogin(t, b, issueLeaf(t, root, key, func(c *x509.Certificate) { c.Subject.CommonName = "server-1" }))
	require.Equal(t, http.StatusOK, resp.StatusCode, "login: %v", resp.Err)
	assert.NotNil(t, resp.Auth.Admission)
}

// =============================================================================
// Metadata equivalence: the mapping renders what metadata_mappings extracts
// =============================================================================

func TestRenderMetadata_EquivalentToExtractCertMetadata(t *testing.T) {
	root := issueCA(t, "Root", newFixtureKey(t), nil)
	key := newFixtureKey(t)
	check := func(t *testing.T, leaf *x509.Certificate, mapping map[string]string) {
		t.Helper()
		want := extractCertMetadata(leaf, mapping)
		naming, err := compileCertFacts("", mapping)
		require.NoError(t, err)
		assert.Equal(t, want, newAdmission(leaf, nil, nil).RenderMetadata(naming), "cert %+v %v %v %v, mapping %v",
			leaf.Subject, leaf.DNSNames, leaf.EmailAddresses, leaf.URIs, mapping)
	}

	full := issueLeaf(t, root, key, func(c *x509.Certificate) {
		c.Subject = pkix.Name{CommonName: "agent-1", OrganizationalUnit: []string{"eng", "ops"}, Organization: []string{"Acme"}}
		c.DNSNames = []string{"a.example.com", "b.example.com"}
		c.EmailAddresses = []string{"agent@example.com"}
		c.URIs = []*url.URL{mustURL(t, "spiffe://example.com/a"), mustURL(t, "urn:example:b")}
	})
	bare := issueLeaf(t, root, key, nil)
	cases := []struct {
		name    string
		leaf    *x509.Certificate
		mapping map[string]string
	}{
		{"every field", full, map[string]string{
			"cn": "name", "serial": "sn", "ou": "units", "org": "orgs",
			"dns_san": "dns", "email_san": "email", "uri_san": "uri",
		}},
		{"identity mappings", full, map[string]string{"cn": "cn", "ou": "ou"}},
		{"no mappings", full, nil},
		{"everything absent", bare, map[string]string{"cn": "name", "ou": "units", "dns_san": "dns", "uri_san": "uri"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { check(t, tc.leaf, tc.mapping) })
	}

	// Generated certificates and mappings: any subset of fields, each to a
	// distinct name or to itself.
	rng := mrand.New(mrand.NewSource(20261020))
	sources := slices.DeleteFunc(certBuiltinFacts(), func(s string) bool { return s == factCA }) // not a metadata_mappings source
	targets := []string{"workload", "team", "who", "id", "where", "what", "how"}
	some := func(pool []string) []string {
		var out []string
		for j := rng.Intn(3); j > 0; j-- {
			out = append(out, pool[rng.Intn(len(pool))])
		}
		return out
	}
	for i := 0; i < 200; i++ {
		leaf := issueLeaf(t, root, key, func(c *x509.Certificate) {
			c.SerialNumber = big.NewInt(rng.Int63())
			c.Subject = pkix.Name{
				CommonName:         []string{"", "agent-1", "a/b"}[rng.Intn(3)],
				OrganizationalUnit: some([]string{"eng", "ops"}),
				Organization:       some([]string{"Acme", "Other"}),
			}
			c.DNSNames = some([]string{"a.example.com", "b.example.com"})
			c.EmailAddresses = some([]string{"a@example.com", "b@other.org"})
			for _, u := range some([]string{"spiffe://example.com/a", "https://x.example.com/p?q=1"}) {
				c.URIs = append(c.URIs, mustURL(t, u))
			}
		})
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
		check(t, leaf, mapping)
	}
}

// The one difference: an empty subject entry is not a fact, so it is dropped
// from the rendering where today's extractor keeps its comma.
func TestRenderMetadata_EmptySubjectEntry(t *testing.T) {
	root := issueCA(t, "Root", newFixtureKey(t), nil)
	leaf := issueLeaf(t, root, newFixtureKey(t), func(c *x509.Certificate) {
		c.Subject = pkix.Name{CommonName: "agent", OrganizationalUnit: []string{"", "eng"}}
	})
	mapping := map[string]string{"ou": "units"}
	assert.Equal(t, map[string]string{"units": ",eng"}, extractCertMetadata(leaf, mapping))
	assert.Equal(t, map[string]string{"units": "eng"}, newAdmission(leaf, nil, nil).RenderMetadata(mustNaming(t, mapping)))
}

// =============================================================================
// Config: entity_kind and facts
// =============================================================================

func TestConfigWrite_Facts(t *testing.T) {
	root := issueCA(t, "Root", newFixtureKey(t), nil)
	b := factsBackend(t, root, nil)
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
		"facts":       map[string]any{"cn": "workload", "ou": "teams"},
	}).StatusCode)
	data := read()
	assert.Equal(t, "human", data["entity_kind"])
	assert.Equal(t, map[string]string{"cn": "workload", "ou": "teams"}, data["facts"])
	n := b.mountFacts.Load()
	require.NotNil(t, n)
	assert.Equal(t, "human", n.Kind)
	assert.Equal(t, []string{"teams", "workload"}, n.Mapping.Mapped())

	// The read is a copy.
	data["facts"].(map[string]string)["cn"] = "changed"
	assert.Equal(t, "workload", b.config.Facts["cn"])

	// A write that leaves them out keeps them.
	require.Equal(t, http.StatusOK, writeConfig(b, map[string]any{"default_role": "reader"}).StatusCode)
	assert.Equal(t, []string{"teams", "workload"}, b.mountFacts.Load().Mapping.Mapped())
	assert.Equal(t, "human", b.mountFacts.Load().Kind)

	// The stored config reloads into the same naming.
	entry, err := b.storageView.Get(ctx, "config")
	require.NoError(t, err)
	var stored map[string]any
	require.NoError(t, entry.DecodeJSON(&stored))
	assert.Equal(t, "human", stored["entity_kind"])
	assert.Equal(t, map[string]any{"cn": "workload", "ou": "teams"}, stored["facts"])
	reloaded, _ := createTestBackend(t)
	reloaded.storageView = b.storageView
	require.NoError(t, reloaded.Initialize(ctx))
	assert.Equal(t, b.mountFacts.Load().Kind, reloaded.mountFacts.Load().Kind)
	assert.Equal(t, b.mountFacts.Load().Mapping.Names(), reloaded.mountFacts.Load().Mapping.Names())

	// An empty map clears the mapping.
	require.Equal(t, http.StatusOK, writeConfig(b, map[string]any{"facts": map[string]any{}}).StatusCode)
	assert.Empty(t, b.mountFacts.Load().Mapping.Mapped())
	assert.Len(t, b.FactNames(), len(certBuiltinFacts()))
}

func TestConfigWrite_FactsRefused(t *testing.T) {
	root := issueCA(t, "Root", newFixtureKey(t), nil)
	cases := []struct {
		name string
		raw  map[string]any
		want string
	}{
		{"bad name", map[string]any{"facts": map[string]any{"cn": "Workload"}}, "facts:"},
		{"reserved mount", map[string]any{"facts": map[string]any{"cn": "mount"}}, "reserved"},
		{"reserved kind", map[string]any{"facts": map[string]any{"ou": "kind"}}, "reserved"},
		{"two sources one name", map[string]any{"facts": map[string]any{"cn": "workload", "dns_san": "workload"}},
			`fact "workload" is produced by both`},
		{"another source onto a built-in", map[string]any{"facts": map[string]any{"cn": "ca"}}, "built-in"},
		{"not a field", map[string]any{"facts": map[string]any{"subject": "subject"}}, `source "subject" is not a field of this mount`},
		{"a pointer", map[string]any{"facts": map[string]any{"/subject/cn": "cn2"}}, "is not a field of this mount"},
		{"non-string name", map[string]any{"facts": map[string]any{"cn": 5}}, "must be a string"},
		{"unknown entity_kind", map[string]any{"entity_kind": "robot"}, "entity_kind:"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := factsBackend(t, root, map[string]any{"facts": map[string]any{"cn": "workload"}})
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
	root := issueCA(t, "Root", newFixtureKey(t), nil)
	bad := map[string]any{
		"trusted_ca_pem": root.pem,
		"facts":          map[string]any{"subject": "subject"},
	}
	leaf := issueLeaf(t, root, newFixtureKey(t), func(c *x509.Certificate) { c.Subject.CommonName = "agent-1" })

	t.Run("from storage", func(t *testing.T) {
		b, _ := createTestBackend(t)
		entry, err := sdklogical.StorageEntryJSON("config", bad)
		require.NoError(t, err)
		require.NoError(t, b.storageView.Put(ctx, entry))

		require.NoError(t, b.Initialize(ctx), "a bad mapping does not fail the load")
		require.NotNil(t, b.config)
		require.Error(t, b.config.FactsConfig.Err())
		assert.Nil(t, b.mountFacts.Load())
		assert.Empty(t, b.FactNames())

		resp := certLogin(t, b, leaf)
		require.Equal(t, http.StatusOK, resp.StatusCode, "logins do not read facts: %v", resp.Err)
		adm := resp.Auth.Admission
		require.NotNil(t, adm)
		adm.MountPath = "auth/cert/"
		for _, name := range append(certBuiltinFacts(), "mount", "kind") {
			assert.Empty(t, factstest.Values(adm, adm.Mount.Load(), name), "fact %q", name)
		}

		// A write that leaves the stored facts in place is told how to replace
		// them, and changes nothing.
		before := b.config
		resp = writeConfig(b, map[string]any{"default_role": "reader"})
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
		assert.EqualError(t, resp.Err, `the stored facts do not compile (facts: source "subject" is not a field of this mount (one of ca, cn, dns_san, email_san, org, ou, serial, uri_san)); send facts (and entity_kind) in this write to replace them`)
		assert.Same(t, before, b.config)

		// Rewriting the facts restores the naming, for this admission too.
		require.Equal(t, http.StatusOK, writeConfig(b, map[string]any{"facts": map[string]any{}}).StatusCode)
		assert.Equal(t, []string{"agent-1"}, factstest.Values(adm, adm.Mount.Load(), "cn"))
	})

	t.Run("from the mount table", func(t *testing.T) {
		backend, err := Factory(ctx, &logical.BackendConfig{Logger: testLogger(), Config: bad})
		require.NoError(t, err, "a bad mapping does not fail the mount")
		b := backend.(*certAuthBackend)
		require.Error(t, b.config.FactsConfig.Err())
		assert.Nil(t, b.mountFacts.Load())
	})
}

// The naming is published with the config it was compiled from, in one
// critical section: a reader holding configMu sees them agree, a lock-free
// reader sees one published naming whole, and logins racing config writes all
// share the mount's MountFacts.
func TestNaming_PublishNeverHalfApplied(t *testing.T) {
	root := issueCA(t, "Root", newFixtureKey(t), nil)
	b := factsBackend(t, root, nil)
	leaf := issueLeaf(t, root, newFixtureKey(t), func(c *x509.Certificate) {
		c.Subject.CommonName = "agent-1"
		c.Subject.OrganizationalUnit = []string{"eng"}
	})
	writes := []map[string]any{
		{"entity_kind": "agent", "facts": map[string]any{"cn": "workload"}},
		{"entity_kind": "human", "facts": map[string]any{"ou": "teams", "ca": "anchor"}},
	}
	whole := func(n *logical.MountNaming) bool {
		switch n.Kind {
		case logical.EntityKindAgent:
			return slices.Equal(n.Mapping.Mapped(), []string{"workload"})
		case logical.EntityKindHuman:
			return slices.Equal(n.Mapping.Mapped(), []string{"anchor", "teams"})
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

	builtins := len(certBuiltinFacts())
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
				resp := certLogin(t, b, leaf)
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
				if n.Kind == logical.EntityKindHuman && len(factstest.Values(adm, n, "anchor")) != 1 {
					report("human naming lost anchor")
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

// convertGlob converts an allowed_common_names, allowed_dns_sans or
// allowed_email_sans pattern (path.Match syntax) to a selector value. '*', '?'
// and '\' mean the same in both, except that a run of '*' is one '*' today
// (none crosses '/') while '**' crosses '/' in a selector, so a run collapses.
// A character class has no selector form and is refused: list each value it
// matches instead. A trailing '\' is refused, as path.Match refuses it.
func convertGlob(p string) (string, error) {
	if p == "" {
		return "", errors.New("an empty pattern matches only an empty value, which is not a fact")
	}
	var b strings.Builder
	for i := 0; i < len(p); i++ {
		switch c := p[i]; c {
		case '\\':
			if i+1 == len(p) {
				return "", fmt.Errorf("pattern %q: trailing \\ escapes nothing", p)
			}
			b.WriteByte(c)
			i++
			b.WriteByte(p[i])
		case '[':
			return "", fmt.Errorf("pattern %q: character class [...] has no selector form; list the values it matches instead", p)
		case '*':
			b.WriteByte(c)
			for i+1 < len(p) && p[i+1] == '*' {
				i++
			}
		default:
			b.WriteByte(c)
		}
	}
	return b.String(), nil
}

// convertSegmentPattern converts an allowed_uri_sans pattern (segment
// wildcards) to a selector value: '+' becomes '*', a trailing '/*' becomes
// '/**' and 'scheme://*' becomes 'scheme://**'; every other segment and the
// scheme are written exactly. A pattern without a scheme matches today only
// URIs without one, which a glob cannot say, so it is refused: write the
// scheme.
func convertSegmentPattern(p string) (string, error) {
	if err := helper.ValidatePattern(p); err != nil {
		return "", err
	}
	scheme, body, ok := strings.Cut(p, "://")
	if !ok {
		return "", fmt.Errorf("pattern %q has no scheme; write the scheme the URIs carry", p)
	}
	if body == "*" {
		return escapeValue(scheme) + "://**", nil
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
	return escapeValue(scheme) + "://" + strings.Join(segs, "/"), nil
}

// pemFingerprints returns the "ca" value of every certificate in a PEM bundle.
func pemFingerprints(t testing.TB, bundle string) []string {
	t.Helper()
	var out []string
	rest := []byte(bundle)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return out
		}
		c, err := x509.ParseCertificate(block.Bytes)
		require.NoError(t, err)
		out = append(out, fingerprint(c))
	}
}

// convertRole converts one role on a mount to a selector rule, pinned to the
// mount. mountCAs are the CAs the mount trusted before (trusted_ca_pem) and
// widened reports whether its converted trusted_ca_pem gained other roles'
// CAs. A role CA becomes a "ca" rule on its fingerprints (the converted
// trusted_ca_pem holds it). A role without one was verified against the
// mount's CAs only; once the mount trusts more, the rule asks for those in
// "ca", and with none it admits nothing (nil). A pattern with no selector
// form is an error.
func convertRole(t testing.TB, mountPath string, role *CertRole, mountCAs []*x509.Certificate, widened bool) (*selector.Rule, error) {
	t.Helper()
	rule := map[string][]string{"mount": {mountPath}}
	globs := func(name string, patterns []string) error {
		for _, p := range patterns {
			v, err := convertGlob(p)
			if err != nil {
				return err
			}
			rule[name] = append(rule[name], v)
		}
		return nil
	}
	if err := globs(factCommonName, role.AllowedCommonNames); err != nil {
		return nil, err
	}
	if err := globs(factDNSSAN, role.AllowedDNSSANs); err != nil {
		return nil, err
	}
	if err := globs(factEmailSAN, role.AllowedEmailSANs); err != nil {
		return nil, err
	}
	for _, p := range role.AllowedURISANs {
		v, err := convertSegmentPattern(p)
		if err != nil {
			return nil, err
		}
		rule[factURISAN] = append(rule[factURISAN], v)
	}
	for _, v := range role.AllowedOrganizationalUnits {
		rule[factOrgUnit] = append(rule[factOrgUnit], escapeValue(v))
	}
	for _, v := range role.AllowedOrganizations {
		rule[factOrg] = append(rule[factOrg], escapeValue(v))
	}
	switch {
	case role.Certificate != "":
		rule[factCA] = pemFingerprints(t, role.Certificate)
	case widened:
		if len(mountCAs) == 0 {
			return nil, nil
		}
		for _, c := range mountCAs {
			rule[factCA] = append(rule[factCA], fingerprint(c))
		}
	}
	compiled, err := selector.Compile(rule)
	require.NoError(t, err, "rule %v", rule)
	return compiled, nil
}

// admitConverted runs the converted model for leaf: verification against the
// converted trusted_ca_pem (pool), the admission built as a login builds it,
// and the rule matched through the naming. A nil rule admits nothing.
func admitConverted(leaf *x509.Certificate, pool []*x509.Certificate, rule *selector.Rule, naming *logical.MountNaming) bool {
	if rule == nil || len(pool) == 0 {
		return false
	}
	roots := x509.NewCertPool()
	for _, c := range pool {
		roots.AddCert(c)
	}
	chains, err := leaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	if err != nil {
		return false
	}
	adm := newAdmission(leaf, chains, nil)
	adm.MountPath = "auth/cert/"
	return rule.Match(factstest.Source{Adm: adm, Naming: naming})
}

// globEscape writes v as a path.Match pattern matching v alone.
func globEscape(v string) string {
	var b strings.Builder
	for i := 0; i < len(v); i++ {
		switch v[i] {
		case '*', '?', '\\', '[':
			b.WriteByte('\\')
		}
		b.WriteByte(v[i])
	}
	return b.String()
}

// uriStrings returns c's URI SANs as strings.
func uriStrings(c *x509.Certificate) []string {
	out := make([]string, len(c.URIs))
	for i, u := range c.URIs {
		out[i] = u.String()
	}
	return out
}

// onlyStars reports whether p is a run of '*': the patterns that match an
// empty value today.
func onlyStars(p string) bool { return p != "" && strings.Trim(p, "*") == "" }

// TestEquivalence_RoleMatcherAndConvertedRule checks, over generated leaf
// certificates, mount CAs and roles, that today's matcher accepts a
// certificate exactly when the converted model does. Today's side is the real
// trust decision login makes before revocation: verification against the
// role's CA, or the mount's (verifyCertForRole), then validateCertConstraints.
// The converted side verifies against the converted trusted_ca_pem (the
// mount's CAs plus every role's) and matches the converted rule.
//
// The domain is the one where the conversion is exact, but for one documented
// narrowing (TestEquivalence_EmptyCommonName): a certificate without a common
// name matched today by a pattern of only '*' has no "cn" fact once converted.
// Patterns hold no character class (the conversion refuses them,
// TestConvert_Refused).
func TestEquivalence_RoleMatcherAndConvertedRule(t *testing.T) {
	naming, err := compileCertFacts("", nil)
	require.NoError(t, err)

	// CAs: three roots, a second certificate for root A's name and key (so a
	// leaf of A verifies to both), and an untrusted one. Keys are reused so
	// generation stays cheap.
	keyA := newFixtureKey(t)
	cas := []*authority{
		issueCA(t, "Root A", keyA, nil),
		issueCA(t, "Root B", newFixtureKey(t), nil),
		issueCA(t, "Root C", newFixtureKey(t), nil),
		issueCA(t, "Root A", keyA, nil),
	}
	untrusted := issueCA(t, "Untrusted", newFixtureKey(t), nil)
	leafKey := newFixtureKey(t)

	rng := mrand.New(mrand.NewSource(20261020))
	pick := func(pool []string) string { return pool[rng.Intn(len(pool))] }
	some := func(pool []string, max int) []string {
		var out []string
		for j := rng.Intn(max + 1); j > 0; j-- {
			out = append(out, pick(pool))
		}
		return out
	}
	subset := func() []*authority {
		var out []*authority
		for _, ca := range cas {
			if rng.Intn(2) == 0 {
				out = append(out, ca)
			}
		}
		return out
	}
	certsOf := func(as []*authority) []*x509.Certificate {
		out := make([]*x509.Certificate, len(as))
		for i, a := range as {
			out[i] = a.cert
		}
		return out
	}
	pemOf := func(as []*authority) string {
		var b strings.Builder
		for _, a := range as {
			b.WriteString(a.pem)
		}
		return b.String()
	}

	cnValues := []string{"agent", "agent-1", "svc.prod", "a/b", "agent/1", "*", ""}
	cnPieces := []string{"agent", "svc", "-", "1", ".", "/", "a", "*", "**", "?", `\*`, `\a`}
	globPattern := func() string {
		var b strings.Builder
		for j := 1 + rng.Intn(3); j > 0; j-- {
			b.WriteString(pick(cnPieces))
		}
		return b.String()
	}
	dnsValues := []string{"a.example.com", "web-1.example.com", "x.other.org"}
	dnsPatterns := []string{"*.example.com", "a.*", "*", "web-?.example.com", "x.other.org", "*.*.org", `\*.example.com`}
	emailValues := []string{"a@example.com", "ops@other.org"}
	emailPatterns := []string{"*@example.com", "a@*", "*@*.org", "ops@other.org", "?@*"}
	uriValues := func() string {
		v := pick([]string{"spiffe", "https"}) + "://" + pick([]string{"example.com", "other.org"})
		for j := rng.Intn(4); j > 0; j-- {
			v += "/" + pick([]string{"dept", "team", "svc", ""})
		}
		return v
	}
	uriPattern := func() string {
		scheme := pick([]string{"spiffe", "https"})
		if rng.Intn(6) == 0 {
			return scheme + "://*"
		}
		segs := []string{pick([]string{"example.com", "other.org", "+"})}
		for j := rng.Intn(3); j > 0; j-- {
			segs = append(segs, pick([]string{"dept", "team", "+"}))
		}
		if rng.Intn(3) == 0 {
			segs = append(segs, "*")
		}
		return scheme + "://" + strings.Join(segs, "/")
	}
	ouValues := []string{"eng", "ops", "a*b", ""}
	orgValues := []string{"Acme", "Other", "x?y"}

	var accepted, refused, narrowed, roleCAs, widenedRoles, globs, uris, exacts int
	for i := 0; i < 1500; i++ {
		// The mount's CAs, the role's own, and other roles' on the mount.
		mountCAs, otherCAs := subset(), subset()
		var roleCA []*authority
		if rng.Intn(3) == 0 {
			roleCA = []*authority{cas[rng.Intn(len(cas))]}
			if rng.Intn(4) == 0 {
				roleCA = append(roleCA, cas[rng.Intn(len(cas))])
			}
			roleCAs++
		}
		pool := slices.Concat(mountCAs, roleCA, otherCAs)
		widened := slices.ContainsFunc(slices.Concat(roleCA, otherCAs), func(a *authority) bool { return !slices.Contains(mountCAs, a) })

		signer := cas[rng.Intn(len(cas))]
		if rng.Intn(8) == 0 {
			signer = untrusted
		}
		leaf := issueLeaf(t, signer, leafKey, func(c *x509.Certificate) {
			c.Subject = pkix.Name{
				CommonName:         pick(cnValues),
				OrganizationalUnit: some(ouValues, 2),
				Organization:       some(orgValues, 2),
			}
			c.DNSNames = some(dnsValues, 2)
			c.EmailAddresses = some(emailValues, 2)
			for j := rng.Intn(3); j > 0; j-- {
				c.URIs = append(c.URIs, mustURL(t, uriValues()))
			}
		})

		// Half the patterns are made from what the leaf carries, so enough
		// roles accept it for agreement to mean something.
		globNear := func(v string) string {
			if v == "" || rng.Intn(2) == 0 {
				return globPattern()
			}
			k := rng.Intn(len(v))
			switch rng.Intn(3) {
			case 0:
				return globEscape(v[:k]) + "*"
			case 1:
				return globEscape(v[:k]) + "?" + globEscape(v[k+1:])
			}
			return globEscape(v)
		}
		uriNear := func() string {
			if len(leaf.URIs) == 0 || rng.Intn(2) == 0 {
				return uriPattern()
			}
			scheme, body, _ := strings.Cut(pick(uriStrings(leaf)), "://")
			segs := strings.Split(body, "/")
			for j := range segs {
				if segs[j] == "" || rng.Intn(3) == 0 {
					segs[j] = "+"
				}
			}
			if k := 1 + rng.Intn(len(segs)); k < len(segs) {
				segs = append(segs[:k], "*")
			}
			return scheme + "://" + strings.Join(segs, "/")
		}

		role := &CertRole{Name: "r", TokenPolicies: []string{"p"}, TokenTTL: "1h", TokenType: "cert_role", Certificate: pemOf(roleCA)}
		for role.AllowedCommonNames == nil && role.AllowedDNSSANs == nil && role.AllowedEmailSANs == nil &&
			role.AllowedURISANs == nil && role.AllowedOrganizationalUnits == nil && role.AllowedOrganizations == nil {
			if rng.Intn(2) == 0 {
				for j := 1 + rng.Intn(2); j > 0; j-- {
					role.AllowedCommonNames = append(role.AllowedCommonNames, globNear(leaf.Subject.CommonName))
				}
				globs++
			}
			if rng.Intn(4) == 0 {
				role.AllowedDNSSANs = append(some(dnsPatterns, 1), pick(dnsPatterns))
			}
			if rng.Intn(4) == 0 {
				role.AllowedEmailSANs = append(some(emailPatterns, 1), pick(emailPatterns))
			}
			if rng.Intn(3) == 0 {
				for j := 1 + rng.Intn(2); j > 0; j-- {
					role.AllowedURISANs = append(role.AllowedURISANs, uriNear())
				}
				uris++
			}
			if rng.Intn(4) == 0 {
				role.AllowedOrganizationalUnits = []string{pick(ouValues[:3]), pick(ouValues[:3])}
				exacts++
			}
			if rng.Intn(4) == 0 {
				role.AllowedOrganizations = []string{pick(orgValues)}
				exacts++
			}
		}

		// Today: the role's trust decision as login makes it.
		config := &CertAuthConfig{}
		if len(mountCAs) > 0 {
			config.caPool, err = buildCAPool(pemOf(mountCAs))
			require.NoError(t, err)
		}
		old := certSatisfiesRole(config, leaf, role)

		// Converted.
		rule, err := convertRole(t, "auth/cert/", role, certsOf(mountCAs), widened)
		require.NoError(t, err, "role %+v", role)
		if role.Certificate == "" && widened {
			widenedRoles++
		}
		got := admitConverted(leaf, certsOf(pool), rule, naming)

		if leaf.Subject.CommonName == "" && slices.ContainsFunc(role.AllowedCommonNames, onlyStars) {
			require.False(t, got, "sample %d: a certificate without a common name has no cn fact", i)
			if old {
				narrowed++
			}
			continue
		}
		require.Equal(t, old, got, "sample %d: leaf %+v %v %v %v from %s, role %+v, mount CAs %d, role CAs %d, other CAs %d",
			i, leaf.Subject, leaf.DNSNames, leaf.EmailAddresses, leaf.URIs, signer.cert.Subject.CommonName,
			role, len(mountCAs), len(roleCA), len(otherCAs))
		if old {
			accepted++
		} else {
			refused++
		}
	}
	// Both outcomes and every feature are exercised, so agreement is not vacuous.
	t.Logf("accepted %d, refused %d, narrowed %d, role CAs %d, widened mounts %d, cn globs %d, uri patterns %d, exact lists %d",
		accepted, refused, narrowed, roleCAs, widenedRoles, globs, uris, exacts)
	assert.Greater(t, accepted, 30)
	assert.Greater(t, refused, 30)
	assert.Greater(t, narrowed, 0)
	assert.Greater(t, roleCAs, 30)
	assert.Greater(t, widenedRoles, 30)
	assert.Greater(t, globs, 30)
	assert.Greater(t, uris, 30)
	assert.Greater(t, exacts, 30)
}

// The documented narrowing: today a pattern of only '*' matches a certificate
// without a common name (path.Match("*", "") holds); converted, an empty
// common name is not a fact, so the rule on "cn" fails.
func TestEquivalence_EmptyCommonName(t *testing.T) {
	naming, err := compileCertFacts("", nil)
	require.NoError(t, err)
	root := issueCA(t, "Root", newFixtureKey(t), nil)
	role := &CertRole{AllowedCommonNames: []string{"*"}}
	rule, err := convertRole(t, "auth/cert/", role, []*x509.Certificate{root.cert}, false)
	require.NoError(t, err)
	config := &CertAuthConfig{}
	config.caPool, _ = buildCAPool(root.pem)

	named := issueLeaf(t, root, newFixtureKey(t), func(c *x509.Certificate) { c.Subject.CommonName = "agent" })
	assert.True(t, certSatisfiesRole(config, named, role))
	assert.True(t, admitConverted(named, []*x509.Certificate{root.cert}, rule, naming))

	unnamed := issueLeaf(t, root, newFixtureKey(t), func(c *x509.Certificate) { c.DNSNames = []string{"a.example.com"} })
	assert.True(t, certSatisfiesRole(config, unnamed, role), "today")
	assert.False(t, admitConverted(unnamed, []*x509.Certificate{root.cert}, rule, naming), "converted")
}

// A run of '*' crosses no '/' today, so it converts to one '*': a '**' left as
// written would cross '/' in a selector and widen the role.
func TestConvert_StarRunsCollapse(t *testing.T) {
	v, err := convertGlob(`a**b\**`)
	require.NoError(t, err)
	assert.Equal(t, `a*b\**`, v)

	naming, err := compileCertFacts("", nil)
	require.NoError(t, err)
	root := issueCA(t, "Root", newFixtureKey(t), nil)
	leaf := issueLeaf(t, root, newFixtureKey(t), func(c *x509.Certificate) { c.Subject.CommonName = "agent/1" })
	role := &CertRole{AllowedCommonNames: []string{"agent**"}}
	config := &CertAuthConfig{}
	config.caPool, _ = buildCAPool(root.pem)
	rule, err := convertRole(t, "auth/cert/", role, []*x509.Certificate{root.cert}, false)
	require.NoError(t, err)
	assert.False(t, certSatisfiesRole(config, leaf, role))
	assert.False(t, admitConverted(leaf, []*x509.Certificate{root.cert}, rule, naming))
}

// Patterns with no selector form are refused by the conversion, never
// converted to something that matches differently.
func TestConvert_Refused(t *testing.T) {
	for _, p := range []string{"agent-[0-9]", "[!a]*", "a[bc]", `agent\`, ""} {
		_, err := convertGlob(p)
		assert.Error(t, err, "pattern %q", p)
	}
	_, err := convertGlob("agent-[0-9]")
	assert.ErrorContains(t, err, "character class")
	_, err = convertRole(t, "auth/cert/", &CertRole{AllowedDNSSANs: []string{"web-[12].example.com"}}, nil, false)
	assert.ErrorContains(t, err, "character class")

	// An escaped '[' is a literal, as it is today.
	v, err := convertGlob(`a\[b`)
	require.NoError(t, err)
	assert.Equal(t, `a\[b`, v)

	// A URI pattern without a scheme matches today only URIs without one.
	for _, p := range []string{"example.com/+", "*", "a/+/*"} {
		_, err := convertSegmentPattern(p)
		assert.ErrorContains(t, err, "no scheme", "pattern %q", p)
	}
	for _, p := range []string{"spiffe://+*", "spiffe://a//b", "spiffe://*/a"} {
		_, err := convertSegmentPattern(p)
		assert.Error(t, err, "pattern %q is invalid today", p)
	}
	cases := map[string]string{
		"spiffe://*":              "spiffe://**",
		"spiffe://+/dept/*":       "spiffe://*/dept/**",
		"spiffe://example.com/a":  "spiffe://example.com/a",
		"https://+/x?y/+":         `https://*/x\?y/*`,
		"spiffe://example.com/**": `spiffe://example.com/\*\*`,
	}
	for in, want := range cases {
		got, err := convertSegmentPattern(in)
		require.NoError(t, err, in)
		assert.Equal(t, want, got, in)
	}
}
