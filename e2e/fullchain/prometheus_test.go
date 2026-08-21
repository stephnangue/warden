//go:build e2e

package fullchain

import (
	"testing"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// prometheus is the provider whose auth scheme is a property of the deployment
// rather than of the credential: a self-hosted server started with
// --web.config.file speaks Basic, a managed one speaks Bearer, and the same key
// cannot mean both. So the scheme sits in mount config beside prometheus_url,
// which already forced one mount per deployment.
//
// That is why these are two mounts rather than two specs. Testing it any other
// way would be testing something the provider no longer does — the scheme used to
// be read from credential data, where nothing could set it, so the Basic branch
// was unreachable and every mount sent Bearer whatever it was configured for.

const (
	prometheusBearerKey = "fc-prometheus-not-a-real-bearer-token"
	// Pre-encoded base64("admin:secret"). Prometheus basic auth takes the
	// encoded pair as the credential, so Warden brokers it verbatim.
	prometheusBasicKey = "YWRtaW46c2VjcmV0"
)

var prometheusEnv = h.ProviderEnv{
	Mount:      "fc-prometheus",
	Type:       "prometheus",
	URLKey:     "prometheus_url",
	CredType:   "api_key",
	CredConfig: map[string]string{"api_key": prometheusBearerKey},
	// No auth_type: the default must be bearer, and a mount that says nothing
	// is the case an upgrade produces.
}

var prometheusBasicEnv = h.ProviderEnv{
	Mount:       "fc-prometheus-basic",
	Type:        "prometheus",
	URLKey:      "prometheus_url",
	CredType:    "api_key",
	ExtraConfig: map[string]any{"auth_type": "basic"},
	CredConfig:  map[string]string{"api_key": prometheusBasicKey},
}

// TestPrometheus_SchemeFollowsMountConfig drives both mounts with the same shape
// of credential and checks that the scheme differs.
//
// The two rows are what distinguish a working config switch from a provider that
// ignores it: before, both would have said "Bearer".
func TestPrometheus_SchemeFollowsMountConfig(t *testing.T) {
	ensureEnv(t)

	cases := []struct {
		name string
		env  h.ProviderEnv
		want string
	}{
		{
			name: "unconfigured mount defaults to bearer",
			env:  prometheusEnv,
			want: "Bearer " + prometheusBearerKey,
		},
		{
			name: "auth_type=basic switches the scheme",
			env:  prometheusBasicEnv,
			want: "Basic " + prometheusBasicKey,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			upstream.Reset()

			status, body, _ := h.ChainRequest(t, leaderPort, tc.env, h.ChainOpts{
				AgentCertPEM: agentCert(t),
				Bearer:       h.FullChainUserJWT(t),
				Role:         tc.env.CertRole(),
			})

			h.AssertChain(t, upstream, status, body, h.ChainWant{
				Status:        200,
				Injected:      map[string]string{"Authorization": tc.want},
				Absent:        h.AlwaysAbsent(),
				UpstreamCalls: 1,
			})
		})
	}
}

// TestPrometheus_ConfigReadReportsTheSchemeInForce checks the operator-visible
// half. A mount whose scheme is wrong and a mount that reports the wrong scheme
// fail the same way from outside — the request works or it does not — so the
// read has to agree with what the request path uses.
func TestPrometheus_ConfigReadReportsTheSchemeInForce(t *testing.T) {
	ensureEnv(t)

	for _, tc := range []struct {
		mount string
		want  string
	}{
		{prometheusEnv.Mount, "bearer"},
		{prometheusBasicEnv.Mount, "basic"},
	} {
		status, body := h.APIRequest(t, "GET", tc.mount+"/config", leaderPort, "")
		if status != 200 {
			t.Fatalf("read %s config (status %d): %s", tc.mount, status, body)
		}
		got := h.JSONPath(h.ParseJSON(t, body), "data.auth_type")
		if got != tc.want {
			t.Errorf("%s auth_type: got %v, want %q", tc.mount, got, tc.want)
		}
	}
}

// TestPrometheus_InvalidSchemeIsRejected pins the hand-written enum check. The
// framework's AllowedValues reaches the OpenAPI document and nothing else, so
// without an explicit guard a typo would be stored and silently serve Bearer —
// a mount configured for Basic, reporting Basic, sending Bearer.
func TestPrometheus_InvalidSchemeIsRejected(t *testing.T) {
	ensureEnv(t)

	status, body := h.APIRequest(t, "PUT", prometheusEnv.Mount+"/config", leaderPort,
		`{"auth_type":"basci"}`)
	if status < 400 || status >= 500 {
		t.Fatalf("writing auth_type=basci: got status %d, want a 4xx (body: %s)", status, body)
	}

	// And the mount is unchanged, rather than left half-written.
	status, body = h.APIRequest(t, "GET", prometheusEnv.Mount+"/config", leaderPort, "")
	if status != 200 {
		t.Fatalf("read config after rejected write (status %d): %s", status, body)
	}
	if got := h.JSONPath(h.ParseJSON(t, body), "data.auth_type"); got != "bearer" {
		t.Errorf("auth_type after rejected write: got %v, want bearer", got)
	}
}
