//go:build e2e

package fullchain

import (
	"net/http"
	"net/http/httptest"
	"testing"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// ibmcloud is the dual-mode gateway that routes by path: each IBM service has
// its own hostname, so the first path segment names the target and the mount
// holds an allowlist of permitted suffixes.
//
// That is also why it needs ibmcloud_url. Left at its default the mount can only
// ever reach public IBM hostnames on 443 — the host comes from the path, which
// carries no port and rejects IP literals — so no local upstream is reachable.
// Setting the URL makes it the single egress base, which is what a VPC private
// endpoint or an enterprise egress gateway looks like, and what lets this row
// exist at all. The host segment is still required and still allow-listed, so
// the request shape a real deployment sends is the shape tested here.
//
// The credential is minted, not held: the source trades its API key for an IAM
// bearer token. IBM IAM's grant is vendor-specific, so a stub stands in via the
// source's own iam_endpoint.

const ibmIAMToken = "fc-ibm-not-a-real-iam-token"

// ibmIAMStub serves the one IBM IAM call the mint makes. Started for the whole
// package alongside the recording upstream, since the source is configured with
// its URL once at setup.
var ibmIAMStub *httptest.Server

func startIBMIAMStub() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/identity/token", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		// Assert the grant the driver is supposed to send, so a change in the
		// exchange surfaces here rather than as a puzzling 200 with a wrong token.
		if r.FormValue("grant_type") != "urn:ibm:params:oauth:grant-type:apikey" {
			http.Error(w, "invalid grant_type", http.StatusBadRequest)
			return
		}
		if r.FormValue("apikey") == "" {
			http.Error(w, "missing apikey", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"access_token":"` + ibmIAMToken + `","token_type":"Bearer","expires_in":3600}`))
	})
	return httptest.NewServer(mux)
}

// ibmcloudEnv is built by ensureEnv once the stub is listening — the source
// config needs its URL, which is not known until then.
var ibmcloudEnv h.ProviderEnv

func buildIBMCloudEnv(iamURL string) h.ProviderEnv {
	return h.ProviderEnv{
		Mount:      "fc-ibmcloud",
		Type:       "ibmcloud",
		URLKey:     "ibmcloud_url",
		CredType:   "ibmcloud_keys",
		SourceType: "ibm",
		SourceConfig: map[string]string{
			"api_key":         "fc-ibm-not-a-real-api-key",
			"iam_endpoint":    iamURL,
			"tls_skip_verify": "true",
		},
		// Bearer-only: mint_method omitted is the gateway's API mode, which is all
		// these rows drive. The COS half is a separate spec now — access_keys, whose
		// pair comes from a referenced spec rather than from config.
		CredConfig: map[string]string{},
	}
}

// TestIBMCloud_EgressBaseCarriesTheServicePath drives the whole chain against a
// configured egress base. The target host still comes from the path and is still
// checked against the allowlist; what changes is where the connection goes.
func TestIBMCloud_EgressBaseCarriesTheServicePath(t *testing.T) {
	ensureEnv(t)

	status, body, _ := h.ChainRequest(t, leaderPort, ibmcloudEnv, h.ChainOpts{
		AgentCertPEM: agentCert(t),
		Bearer:       h.FullChainUserJWT(t),
		Role:         ibmcloudEnv.CertRole(),
		Path:         "resource-controller.cloud.ibm.com/v2/resource_instances",
	})

	h.AssertChain(t, upstream, status, body, h.ChainWant{
		Status:        200,
		Injected:      map[string]string{"Authorization": "Bearer " + ibmIAMToken},
		Absent:        h.AlwaysAbsent(),
		UpstreamCalls: 1,
	})

	// The host stays in the path. An egress hop fronting several IBM services
	// has to know which one was addressed, and this mount reaches several by
	// definition — drop it and every service becomes the same URL.
	const want = "/resource-controller.cloud.ibm.com/v2/resource_instances"
	if got := upstream.Last(t).Path; got != want {
		t.Errorf("upstream path = %q, want %q", got, want)
	}
}

// TestIBMCloud_AllowlistStillAppliesBehindAnEgressBase is the row that makes the
// override safe to have. A configured base must not become a way to reach hosts
// the mount's allowlist refuses — the check happens either way, so the same
// client request is accepted or refused identically.
func TestIBMCloud_AllowlistStillAppliesBehindAnEgressBase(t *testing.T) {
	ensureEnv(t)

	status, body, _ := h.ChainRequest(t, leaderPort, ibmcloudEnv, h.ChainOpts{
		AgentCertPEM: agentCert(t),
		Bearer:       h.FullChainUserJWT(t),
		Role:         ibmcloudEnv.CertRole(),
		Path:         "evil.example.com/v2/resource_instances",
	})

	// A refusal, specifically — not merely "not 200". A redirect or a 5xx would
	// also fail an inequality check while meaning something else entirely.
	if status != http.StatusBadRequest {
		t.Fatalf("status %d, want 400 for a host outside the allowlist (body: %s)", status, string(body))
	}
	if n := len(upstream.Requests()); n != 0 {
		t.Errorf("upstream received %d requests for a refused host, want 0", n)
	}
}
