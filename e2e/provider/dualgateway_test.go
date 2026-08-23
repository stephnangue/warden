//go:build e2e

package provider

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509/pkix"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// The dual-mode gateway providers — scaleway, ovh, cloudflare, ibmcloud — were
// unreachable by this suite until the config apply path was fixed. Two defects
// closed off every ordering: the upstream URL could only be set at mount time,
// the agent leg only by a later config write, and that write reset every key it
// did not name, including the URL.
//
// These rows drive scaleway, standing in for all four: they share one SDK, and
// the config path is entirely inside it.

const (
	dgMount     = "dg-scaleway"
	dgRole      = "dg-agent"
	dgAgentCN   = "dg-agent-cert"
	dgAccessKey = "SCWE2EACCESSKEY00000"
	dgSecretKey = "e2e-secret-0000-0000-000000000000"
)

// setupDualGateway mounts scaleway pointed at upstreamURL and rigs the agent leg
// that lets a request through it: a cert role bound to a credential spec, and a
// policy granting the gateway path.
//
// extraConfig is merged into the *mount-time* configuration, which is the point
// of the exercise — a mount arriving fully configured in one step is only
// possible once mount-time transparent-auth settings are honoured.
func setupDualGateway(t *testing.T, port int, upstreamURL string, extraConfig map[string]any) string {
	t.Helper()

	teardownDualGateway(t, port)
	// Unmounting an auth method and remounting it in the same breath races the
	// auth table update and answers 500. Other tests in this package tear down
	// auth/cert on their way out, so this settles before claiming it again.
	time.Sleep(time.Second)

	caCertPEM, caKey := h.SetupCertAuth(t, port)
	t.Cleanup(func() { teardownDualGateway(t, port) })

	cfg := map[string]any{
		"scaleway_url":   upstreamURL,
		"auto_auth_path": "auth/cert/",
		"default_role":   dgRole,
	}
	for k, v := range extraConfig {
		cfg[k] = v
	}

	mustDG(t, port, "POST", "sys/providers/"+dgMount, mustJSONBody(t, map[string]any{
		"type":        "scaleway",
		"description": "e2e dual-mode gateway",
		"config":      cfg,
	}), "mount scaleway provider")
	time.Sleep(time.Second)

	mustDG(t, port, "POST", "sys/cred/sources/"+dgMount+"-src",
		`{"type":"local"}`, "create credential source")

	mustDG(t, port, "POST", "sys/cred/specs/"+dgMount+"-cred", mustJSONBody(t, map[string]any{
		"type":   "scaleway_keys",
		"source": dgMount + "-src",
		"config": map[string]string{
			"access_key": dgAccessKey,
			"secret_key": dgSecretKey,
		},
	}), "create credential spec")

	policy := fmt.Sprintf(
		"path %q {\n  capabilities = [\"read\",\"create\",\"update\",\"delete\",\"list\"]\n}\n"+
			"path %q {\n  capabilities = [\"read\",\"create\",\"update\",\"delete\",\"list\"]\n}\n",
		dgMount+"/gateway*", dgMount+"/role/+/gateway*")
	mustDG(t, port, "POST", "sys/policies/cbp/"+dgMount+"-access",
		mustJSONBody(t, map[string]any{"policy": policy}), "create policy")

	mustDG(t, port, "POST", "auth/cert/role/"+dgRole, mustJSONBody(t, map[string]any{
		"allowed_common_names": []string{dgAgentCN},
		"token_policies":       []string{dgMount + "-access"},
		"cred_spec_name":       dgMount + "-cred",
		"token_ttl":            3600,
	}), "create cert role")

	clientCertPEM, _ := h.GenerateClientCert(t, caCertPEM, caKey, dgAgentCN)
	return clientCertPEM
}

// teardownDualGateway removes everything setup creates, ignoring what is not
// there. Run before setup as well as after: a run that failed midway would
// otherwise turn every later attempt into a 409 and hide the original failure.
func teardownDualGateway(t *testing.T, port int) {
	t.Helper()
	for _, p := range []string{
		"auth/cert/role/" + dgRole,
		"sys/policies/cbp/" + dgMount + "-access",
		"sys/cred/specs/" + dgMount + "-cred",
		"sys/cred/sources/" + dgMount + "-src",
		"sys/providers/" + dgMount,
	} {
		h.APIRequest(t, "DELETE", p, port, "")
	}
	// auth/cert stores a single trusted CA, so leaving it mounted would hand
	// the next test in this package a CA that does not match its certificates.
	h.TeardownCertAuth(t, port)
}

// dgRequest drives the transparent gateway leg: the agent proves itself with a
// client certificate and the role comes from the URL, so no header carries a
// token and the mount mints the credential itself.
func dgRequest(t *testing.T, port int, apiPath, clientCertPEM string) (int, []byte) {
	t.Helper()
	u := fmt.Sprintf("%s/v1/%s/role/%s/gateway%s", h.NodeURL(port), dgMount, dgRole, apiPath)
	return h.DoRequest(t, "GET", u, map[string]string{
		"X-SSL-Client-Cert": h.URLEncodePEM(clientCertPEM),
	}, "")
}

// B5: mount-time configuration carries the agent leg, not just the URL.
// Accepting auto_auth_path at mount and discarding it left the transparent path
// unreachable except through a config write.
func TestDualGateway_MountTimeConfigConfiguresTheAgentLeg(t *testing.T) {
	port := h.GetLeaderPort(t)

	upstream := h.StartRecordingUpstream(t)
	defer upstream.Close()

	clientCertPEM := setupDualGateway(t, port, upstream.URL, map[string]any{
		"tls_skip_verify": true, // permits the http:// scheme on a local listener
	})

	status, body := dgRequest(t, port, "/instance/v1/zones/fr-par-1/servers", clientCertPEM)
	if status != 200 {
		t.Fatalf("transparent gateway request: status %d, body %s", status, string(body))
	}

	got := upstream.Last(t)
	if got.Header.Get("X-Auth-Token") != dgSecretKey {
		t.Errorf("upstream X-Auth-Token = %q, want the minted secret key",
			got.Header.Get("X-Auth-Token"))
	}
	if got.Path != "/instance/v1/zones/fr-par-1/servers" {
		t.Errorf("upstream path = %q, want the API path with the gateway prefix stripped", got.Path)
	}
}

// B4: a config write names one key; every other key must survive it. Before the
// fix this sequence repointed the mount at https://api.scaleway.com and reset
// the timeout, and reported success doing it.
func TestDualGateway_PartialConfigWritePreservesTheRest(t *testing.T) {
	port := h.GetLeaderPort(t)

	upstream := h.StartRecordingUpstream(t)
	defer upstream.Close()

	clientCertPEM := setupDualGateway(t, port, upstream.URL, map[string]any{
		"tls_skip_verify": true,
		"timeout":         "2m",
	})

	// Name one key, and only that key.
	mustDG(t, port, "PUT", dgMount+"/config",
		`{"default_role":"`+dgRole+`"}`, "partial config write")

	status, body := h.APIRequest(t, "GET", dgMount+"/config", port, "")
	if status != 200 {
		t.Fatalf("read config: status %d, body %s", status, string(body))
	}
	var resp struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("unmarshal config: %v\nbody: %s", err, string(body))
	}

	if got := resp.Data["scaleway_url"]; got != upstream.URL {
		t.Errorf("scaleway_url = %v, want %q — the write reset it", got, upstream.URL)
	}
	if got := resp.Data["timeout"]; got != "2m0s" {
		t.Errorf("timeout = %v, want 2m0s — the write reset it", got)
	}
	if got := resp.Data["auto_auth_path"]; got != "auth/cert/" {
		t.Errorf("auto_auth_path = %v, want auth/cert/", got)
	}

	// The read agreeing is not enough — a stored value and a served one can
	// disagree. Only traffic proves the mount still points where it says.
	upstream.Reset()
	status, body = dgRequest(t, port, "/instance/v1/zones/fr-par-1/servers", clientCertPEM)
	if status != 200 {
		t.Fatalf("request after partial write: status %d, body %s", status, string(body))
	}
	if len(upstream.Requests()) == 0 {
		t.Fatal("request did not reach the local upstream — the mount was repointed")
	}
}

// B6: an upstream signed by a private authority. Every mount of every dual-mode
// provider shared one transport with a fixed TLS config, so ca_data was masked
// in output while being impossible to set.
func TestDualGateway_PrivateCAUpstream(t *testing.T) {
	port := h.GetLeaderPort(t)

	upstream, caData := startPrivateCAUpstream(t)
	defer upstream.Close()

	clientCertPEM := setupDualGateway(t, port, upstream.URL, map[string]any{
		"ca_data": caData,
	})

	status, body := dgRequest(t, port, "/instance/v1/zones/fr-par-1/servers", clientCertPEM)
	if status != 200 {
		t.Fatalf("private-CA upstream: status %d, body %s", status, string(body))
	}

	// The same upstream without the authority must fail, or the row above
	// proves only that the handshake happened, not that ca_data caused it.
	mustDG(t, port, "PUT", dgMount+"/config", `{"ca_data":""}`, "drop ca_data")

	status, _ = dgRequest(t, port, "/instance/v1/zones/fr-par-1/servers", clientCertPEM)
	if status == 200 {
		t.Error("upstream signed by an untrusted authority was reached anyway")
	}
}

// startPrivateCAUpstream serves TLS under a CA no system root store knows,
// returning it as the base64-encoded PEM the ca_data field takes.
func startPrivateCAUpstream(t *testing.T) (*httptest.Server, string) {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "dualgateway-e2e-ca"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}

	srvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate server key: %v", err)
	}
	srvTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTmpl, caCert, &srvKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create server cert: %v", err)
	}

	// NewTLSServer generates its own certificate and cannot be handed one, so
	// the server is built unstarted and its TLS config supplied first.
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{srvDER},
			PrivateKey:  srvKey,
		}},
	}
	srv.StartTLS()

	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	return srv, base64.StdEncoding.EncodeToString(caPEM)
}

// --- small local helpers ---

func mustDG(t *testing.T, port int, method, path, body, what string) {
	t.Helper()
	status, resp := h.APIRequest(t, method, path, port, body)
	if status < 200 || status >= 300 {
		t.Fatalf("%s: status %d, body %s", what, status, string(resp))
	}
}

func mustJSONBody(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal request body: %v", err)
	}
	return string(b)
}
