//go:build e2e

package fullchain

import (
	"strings"
	"testing"
	"time"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// vault is the channels token extractor with the native header second, like
// anthropic — and the only mount in the package whose credential is real.
//
// Every other provider here mints from a local source, so its "credential" is a
// constant copied out of a spec config. vault_token refuses a local source, so
// this mount's source has to trade an AppRole secret for a service token at the
// harness Vault on :8200 while the mount itself proxies to the recording
// upstream. Two addresses, deliberately: the recorder says what was forwarded,
// and the real Vault says whether what was forwarded was ever a token at all.
// That second half is what no other file in this package can assert.
//
// It also carries the outbound shapes no other provider has: a path rewritten on
// the way through, and a set of paths forwarded with no credential whatsoever.

const (
	vaultAddr         = "http://127.0.0.1:8200"
	vaultApproleMount = "e2e_approle"

	// Token role seeded by setup.sh. Its minted tokens carry exactly one policy,
	// which is what makes the lookup in T1 an assertion rather than a ping.
	vaultTokenRole   = "e2e-secrets-reader"
	vaultTokenPolicy = "e2e-secrets-reader"

	// The suite's own AppRole role, not the shared warden-e2e-role several other
	// suites drive. A rotating source destroys the secret_id it replaces, so two
	// suites sharing one role can strand each other's credential between runs.
	// A suite-local role can only ever strand itself.
	vaultApproleRole = "fc-warden-vault"
	vaultRoleID      = "fc-vault-role-id-not-a-real-id"
	vaultSecretID    = "fc-vault-secret-id-not-a-real-secret"

	// The rotation row's own everything, down to a second AppRole role: it
	// rotates every 15s once created, and must not be able to pull the secret out
	// from under the mount every other test here drives.
	vaultRotApproleRole = "fc-warden-vault-rot"
	vaultRotRoleID      = "fc-vault-rot-role-id-not-a-real-id"
	vaultRotSecretID    = "fc-vault-rot-secret-id-not-a-real-secret"
	vaultRotSource      = "fc-vault-rot-src"
	vaultRotSpec        = "fc-vault-rot-cred"
	vaultRotAgentRole   = "fc-vault-rot-agent"

	// The wrong-credential-type row's locals.
	vaultWrongCredSource = "fc-vault-wrongcred-src"
	vaultWrongCredSpec   = "fc-vault-wrongcred"
	vaultWrongCredRole   = "fc-vault-wrongcred-agent"
	vaultWrongCredKey    = "fc-vault-not-a-vault-token"

	// Service tokens are prefixed. A minted credential that does not start with
	// this is not a token this mount could have got from Vault.
	vaultServiceTokenPrefix = "hvs."
)

var vaultEnv = h.ProviderEnv{
	Mount:      "fc-vault",
	Type:       "vault",
	URLKey:     "vault_address",
	CredType:   "vault_token",
	SourceType: "hvault",
	SourceConfig: map[string]string{
		"vault_address": vaultAddr,
		"auth_method":   "approle",
		"role_id":       vaultRoleID,
		"secret_id":     vaultSecretID,
		"approle_mount": vaultApproleMount,
		// Required for the source to be rotatable at all, and the store refuses an
		// approle source that is not.
		"role_name": vaultApproleRole,
	},
	// Deliberately a day. The store requires a period on this source type, and a
	// source that carries one really does rotate — a short one here would fire
	// partway through an unrelated test in this package and change its credential
	// mid-run. The row that means to watch a rotation brings its own source.
	SourceRotationPeriod: 86400,
	CredConfig: map[string]string{
		"mint_method": "vault_token",
		"token_role":  vaultTokenRole,
	},
}

// seedVaultApproleRole creates one AppRole role in the harness Vault with a
// pinned role_id and secret_id, mirroring what setup.sh does for the shared role.
//
// It runs from the test rather than from setup.sh so the suite stays runnable
// against a cluster that is already up: adding it to the harness script instead
// would leave every existing cluster unable to run this package until it was torn
// down and rebuilt. Re-running is safe — role and role_id writes are updates, and
// the secret_id is registered best-effort.
//
// The policies match setup.sh's: e2e-warden-service is what lets the source both
// mint tokens and rotate its own secret_id.
func seedVaultApproleRole(t *testing.T, role, roleID, secretID string) {
	t.Helper()

	mustVault := func(path, body, what string) {
		t.Helper()
		switch status, resp := h.VaultDirectRequest(t, "POST", path, body); status {
		case 200, 201, 204:
		default:
			t.Fatalf("%s (status %d): %s", what, status, resp)
		}
	}

	mustVault("auth/"+vaultApproleMount+"/role/"+role, `{
		"token_policies":["default","e2e-warden-service"],
		"token_ttl":"3600","token_period":"3600","token_type":"service","bind_secret_id":true}`,
		"create the suite AppRole role "+role)

	mustVault("auth/"+vaultApproleMount+"/role/"+role+"/role-id",
		`{"role_id":"`+roleID+`"}`,
		"pin the role_id for "+role)

	// Not mustVault: a re-run against a cluster that still holds this secret_id
	// gets a refusal, and that refusal means the secret is already there — which
	// is the state the caller wanted. A run whose secret really is missing fails
	// at the source create instead, where the error names the login.
	h.VaultDirectRequest(t, "POST", "auth/"+vaultApproleMount+"/role/"+role+"/custom-secret-id",
		`{"secret_id":"`+secretID+`"}`)
}

// mintedVaultToken returns the token the upstream received, having established
// that it is a service token and none of the credentials the caller sent.
//
// The second half is the point. A provider that forwarded the caller's own header
// untouched would satisfy any assertion that merely finds a token upstream.
func mintedVaultToken(t *testing.T, inbound ...string) string {
	t.Helper()

	got := upstream.Last(t).Header.Get("X-Vault-Token")
	if !strings.HasPrefix(got, vaultServiceTokenPrefix) {
		t.Fatalf("upstream X-Vault-Token = %q, want a service token (%q prefix)", got, vaultServiceTokenPrefix)
	}
	for _, sent := range inbound {
		if sent != "" && got == sent {
			t.Fatalf("upstream X-Vault-Token is a credential the caller sent, not a minted one")
		}
	}
	return got
}

// assertVaultTokenUsable looks the token up in the real Vault and checks the
// policy it carries.
//
// This is the assertion the rest of the package cannot make: it passes only if
// the AppRole login, the token-role mint and the injection all happened against a
// live Vault, and it fails for a well-formed string that was never issued.
func assertVaultTokenUsable(t *testing.T, token string) {
	t.Helper()

	status, body := h.VaultDirectRequest(t, "POST", "auth/token/lookup", `{"token":"`+token+`"}`)
	if status != 200 {
		t.Fatalf("looking the minted token up in Vault: status %d, body: %s", status, body)
	}

	policies, _ := h.JSONPath(h.ParseJSON(t, body), "data.policies").([]interface{})
	for _, p := range policies {
		if p == vaultTokenPolicy {
			return
		}
	}
	t.Errorf("minted token carries policies %v, want one of them to be %q", policies, vaultTokenPolicy)
}

// TestVault_MintedServiceTokenReachesUpstream is this mount's reference shape,
// and the only row in the package that closes the loop on a real credential.
//
// The decoys are the inert ones only. X-Vault-Token is this provider's native
// agent channel, so sending it as a decoy would occupy the agent slot rather than
// exercise the strip — the same reason anthropic does not decoy x-api-key. That
// header's replacement is pinned by TestVault_NativeChannelCarriesAgent instead.
func TestVault_MintedServiceTokenReachesUpstream(t *testing.T) {
	ensureEnv(t)

	userJWT := h.FullChainUserJWT(t)
	probe := h.ProbePath("vault-kv")
	decoys := h.InertDecoyHeaders()

	status, body, _ := h.ChainRequest(t, leaderPort, vaultEnv, h.ChainOpts{
		AgentCertPEM: agentCert(t),
		Bearer:       userJWT,
		Role:         vaultEnv.CertRole(),
		Path:         probe,
		Headers:      decoys,
	})

	h.AssertChain(t, upstream, status, body, h.ChainWant{
		Status: 200,
		// This provider does not put its credential in Authorization, so the
		// caller's Bearer must not survive the hop.
		Absent:        h.AlwaysAbsent("Authorization"),
		UpstreamCalls: 1,
	})

	inbound := []string{userJWT}
	for _, v := range decoys {
		inbound = append(inbound, v)
	}
	assertVaultTokenUsable(t, mintedVaultToken(t, inbound...))

	if got, want := upstream.Last(t).Path, "/v1/"+probe; got != want {
		t.Errorf("upstream path = %q, want %q", got, want)
	}
	h.AssertAuditUser(t, leaderPort, probe, h.FullChainUserSubject)
}

// TestVault_GatewayPrependsV1Exactly pins the path rewrite, which only a
// recording upstream can see.
//
// Vault's API lives under /v1, and a caller may or may not have spelled it. The
// hazard is symmetric: a gateway that never prepends breaks every bare path, and
// one that always prepends turns a spelled-out path into /v1/v1/... — which
// Vault answers with a 404 that looks like a missing secret rather than a
// mangled request.
func TestVault_GatewayPrependsV1Exactly(t *testing.T) {
	ensureEnv(t)

	bare := "secret/data/" + h.ProbePath("vault-bare")
	spelled := "v1/secret/data/" + h.ProbePath("vault-v1")

	cases := []struct {
		name string
		send string
		want string
	}{
		{"a bare path gains /v1", bare, "/v1/" + bare},
		{"a spelled-out /v1 is not doubled", spelled, "/" + spelled},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			upstream.Reset()

			status, body, _ := h.ChainRequest(t, leaderPort, vaultEnv, h.ChainOpts{
				AgentCertPEM: agentCert(t),
				Bearer:       h.FullChainUserJWT(t),
				Role:         vaultEnv.CertRole(),
				Path:         tc.send,
			})

			h.AssertChain(t, upstream, status, body, h.ChainWant{
				Status:        200,
				Absent:        h.AlwaysAbsent("Authorization"),
				UpstreamCalls: 1,
			})
			if got := upstream.Last(t).Path; got != tc.want {
				t.Errorf("sent %q, upstream saw %q, want %q", tc.send, got, tc.want)
			}
		})
	}
}

// TestVault_NativeChannelCarriesAgent puts the agent in X-Vault-Token rather
// than a certificate. It is consulted after X-Warden-Token and leaves
// Authorization free, so both principals resolve from a request carrying no
// certificate at all.
//
// It is also where the strip of the native header becomes load-bearing: the same
// header name arrives carrying the caller's JWT and leaves carrying a minted
// Vault token, so a provider that forwarded it untouched would hand the upstream
// a credential that is not a Vault token at all.
func TestVault_NativeChannelCarriesAgent(t *testing.T) {
	ensureEnv(t)
	useJWTAgentLeg(t, vaultEnv)

	agentJWT := h.GetDefaultJWT(t)
	probe := h.ProbePath("vault-native-channel")

	status, body, _ := h.ChainRequest(t, leaderPort, vaultEnv, h.ChainOpts{
		Bearer:  h.FullChainUserJWT(t),
		Role:    vaultEnv.JWTAgentRole(),
		Headers: map[string]string{"X-Vault-Token": agentJWT},
		Path:    probe,
	})

	h.AssertChain(t, upstream, status, body, h.ChainWant{
		Status:        200,
		Absent:        h.AlwaysAbsent("Authorization"),
		UpstreamCalls: 1,
	})
	assertVaultTokenUsable(t, mintedVaultToken(t, agentJWT))
	h.AssertAuditUser(t, leaderPort, probe, h.FullChainUserSubject)
}

// TestVault_OperatorTokenOutranksNativeChannel is the vault copy of the
// anthropic row: X-Warden-Token is consulted first, X-Vault-Token second, so a
// request carrying both resolves the operator token into the agent slot.
//
// Neither credential can produce a successful request, which is why the failure
// shape is the observable. The operator token resolves and dies at the mint for
// want of a bound spec — a 400. Had the JWT won the slot instead, it would have
// resolved to the mount's own role and the request would have succeeded.
func TestVault_OperatorTokenOutranksNativeChannel(t *testing.T) {
	ensureEnv(t)
	useJWTAgentLeg(t, vaultEnv)

	status, body, _ := h.ChainRequest(t, leaderPort, vaultEnv, h.ChainOpts{
		WardenToken: h.RootToken(t),
		Role:        vaultEnv.JWTAgentRole(),
		Headers:     map[string]string{"X-Vault-Token": h.GetDefaultJWT(t)},
	})

	h.AssertChain(t, upstream, status, body, h.ChainWant{
		Status:        400,
		UpstreamCalls: 0,
	})
	if !strings.Contains(string(body), "credential spec") {
		t.Errorf("want the mint to fail for a missing credential spec, got: %s", body)
	}
}

// TestVault_PolicyDenialStopsBeforeUpstream is the general denial row, and it
// matters more on this mount than on any other: the credential a forwarded
// request would carry is a live Vault token with real read capability, so a
// policy that refused only after forwarding would have already issued and leaked
// one. The upstream call count is the assertion, not the status.
func TestVault_PolicyDenialStopsBeforeUpstream(t *testing.T) {
	ensureEnv(t)

	status, body, _ := h.ChainRequest(t, leaderPort, vaultEnv, h.ChainOpts{
		AgentCertPEM: agentCert(t),
		Bearer:       h.FullChainUserJWT(t),
		Role:         vaultEnv.DenyRole(),
	})

	h.AssertChain(t, upstream, status, body, h.ChainWant{
		Status:        403,
		UpstreamCalls: 0,
	})
}

// setupVaultWrongCredEnv binds an api_key spec to a role on the vault mount:
// everything about the request is right except the type of credential it mints.
func setupVaultWrongCredEnv(t *testing.T) {
	t.Helper()

	mustWrite := func(path, body, what string) {
		t.Helper()
		switch status, resp := h.APIRequest(t, "POST", path, leaderPort, body); status {
		case 200, 201, 204:
		default:
			t.Fatalf("%s (status %d): %s", what, status, resp)
		}
	}

	// Consumers before what they reference, which is also what clears anything a
	// killed run left behind — a leftover would 409 the creates below.
	clear := func() {
		h.APIRequest(t, "DELETE", "auth/cert/role/"+vaultWrongCredRole, leaderPort, "")
		h.APIRequest(t, "DELETE", "sys/cred/specs/"+vaultWrongCredSpec, leaderPort, "")
		h.APIRequest(t, "DELETE", "sys/cred/sources/"+vaultWrongCredSource, leaderPort, "")
	}
	clear()
	t.Cleanup(clear)

	mustWrite("sys/cred/sources/"+vaultWrongCredSource, `{"type":"local"}`,
		"create the wrong-type source")

	mustWrite("sys/cred/specs/"+vaultWrongCredSpec, `{
		"type":"api_key","source":"`+vaultWrongCredSource+`",
		"config":{"api_key":"`+vaultWrongCredKey+`"}}`,
		"create the wrong-type spec")

	// The mount's own policy, so authorization succeeds and the credential type is
	// the only thing left that can refuse the request.
	mustWrite("auth/cert/role/"+vaultWrongCredRole, `{
		"allowed_common_names":["`+h.FullChainAgentCN+`"],
		"token_policies":["`+vaultEnv.Policy()+`"],
		"cred_spec_name":"`+vaultWrongCredSpec+`","token_ttl":3600}`,
		"create the wrong-type agent role")
}

// TestVault_NonVaultTokenCredentialIsRefused pins the provider's credential-type
// gate.
//
// An operator can bind any spec to any role, so a mount can be handed a
// credential it has no way to use. The only safe answer is to refuse: the
// alternative is forwarding the request with no token, which Vault would answer
// with its own 403 — turning a misconfiguration into what reads like a
// permissions problem at the far end, and doing it after the request left.
func TestVault_NonVaultTokenCredentialIsRefused(t *testing.T) {
	ensureEnv(t)
	setupVaultWrongCredEnv(t)

	status, body, _ := h.ChainRequest(t, leaderPort, vaultEnv, h.ChainOpts{
		AgentCertPEM: agentCert(t),
		Bearer:       h.FullChainUserJWT(t),
		Role:         vaultWrongCredRole,
	})

	h.AssertChain(t, upstream, status, body, h.ChainWant{
		Status:        401,
		UpstreamCalls: 0,
	})
}

// TestVault_UnauthenticatedPKIPathCarriesNoToken covers the one shape in the
// package where a request is forwarded with no credential at all.
//
// Vault serves a handful of PKI read paths — CA certificates, CRLs — without
// authentication, and clients fetch them without a token. Warden forwards those
// verbatim and lets Vault's own ACL decide, so the assertion is the absence of a
// token upstream: a gateway that helpfully minted one would be issuing a
// credential for a request that never authenticated.
//
// The path list is anchored on v1/, matched after the gateway prefix, so these
// requests spell the v1 out.
func TestVault_UnauthenticatedPKIPathCarriesNoToken(t *testing.T) {
	ensureEnv(t)

	t.Run("a listed PKI path is forwarded without credentials", func(t *testing.T) {
		upstream.Reset()

		status, body, _ := h.ChainRequest(t, leaderPort, vaultEnv, h.ChainOpts{
			Path: "v1/pki/ca/pem",
		})

		h.AssertChain(t, upstream, status, body, h.ChainWant{
			Status:        200,
			Absent:        h.AlwaysAbsent("Authorization", "X-Vault-Token"),
			UpstreamCalls: 1,
		})
		if got, want := upstream.Last(t).Path, "/v1/pki/ca/pem"; got != want {
			t.Errorf("upstream path = %q, want %q", got, want)
		}
	})

	// Without this the row above would pass against a mount that had stopped
	// authenticating anything at all.
	t.Run("an unlisted path without credentials is refused", func(t *testing.T) {
		upstream.Reset()

		status, body, _ := h.ChainRequest(t, leaderPort, vaultEnv, h.ChainOpts{
			Path: "v1/secret/data/" + h.ProbePath("vault-noauth"),
		})

		h.AssertChain(t, upstream, status, body, h.ChainWant{
			Status:        401,
			UpstreamCalls: 0,
		})
	})
}

// setupVaultRotationEnv builds a second, throwaway chain over its own AppRole
// role, rotating as fast as the cluster's configured floor allows.
//
// Everything is test-local, the AppRole role included. Rotation destroys the
// secret_id it replaces, so a rotator pointed at the package's shared role would
// invalidate the credential every other test in this file depends on.
func setupVaultRotationEnv(t *testing.T) {
	t.Helper()

	seedVaultApproleRole(t, vaultRotApproleRole, vaultRotRoleID, vaultRotSecretID)

	mustWrite := func(path, body, what string) {
		t.Helper()
		switch status, resp := h.APIRequest(t, "POST", path, leaderPort, body); status {
		case 200, 201, 204:
		default:
			t.Fatalf("%s (status %d): %s", what, status, resp)
		}
	}

	clear := func() {
		h.APIRequest(t, "DELETE", "auth/cert/role/"+vaultRotAgentRole, leaderPort, "")
		h.APIRequest(t, "DELETE", "sys/cred/specs/"+vaultRotSpec, leaderPort, "")
		h.APIRequest(t, "DELETE", "sys/cred/sources/"+vaultRotSource, leaderPort, "")
	}
	clear()
	// Deleting the source is what unregisters it from the scheduler; without this
	// it would keep rotating for the rest of the package's run.
	t.Cleanup(clear)

	mustWrite("sys/cred/sources/"+vaultRotSource, `{
		"type":"hvault","rotation_period":15,
		"config":{"vault_address":"`+vaultAddr+`","auth_method":"approle",
			"role_id":"`+vaultRotRoleID+`","secret_id":"`+vaultRotSecretID+`",
			"approle_mount":"`+vaultApproleMount+`","role_name":"`+vaultRotApproleRole+`"}}`,
		"create the rotating source")

	mustWrite("sys/cred/specs/"+vaultRotSpec, `{
		"type":"vault_token","source":"`+vaultRotSource+`",
		"config":{"mint_method":"vault_token","token_role":"`+vaultTokenRole+`"}}`,
		"create the rotating source's spec")

	// A short token_ttl so the request made after the rotation is a new session
	// that has to mint again, rather than one served from the cache the first
	// request populated.
	mustWrite("auth/cert/role/"+vaultRotAgentRole, `{
		"allowed_common_names":["`+h.FullChainAgentCN+`"],
		"token_policies":["`+vaultEnv.Policy()+`"],
		"cred_spec_name":"`+vaultRotSpec+`","token_ttl":60}`,
		"create the rotating agent role")
}

// vaultSecretIDCount returns how many secret_id accessors an AppRole role holds.
func vaultSecretIDCount(t *testing.T, role string) int {
	t.Helper()

	status, body := h.VaultDirectRequest(t, "GET",
		"auth/"+vaultApproleMount+"/role/"+role+"/secret-id?list=true", "")
	if status == 404 {
		// Vault answers a role with no secret_ids with a 404 rather than an empty
		// list.
		return 0
	}
	if status != 200 {
		t.Fatalf("listing secret_id accessors for %s: status %d, body: %s", role, status, body)
	}
	keys, _ := h.JSONPath(h.ParseJSON(t, body), "data.keys").([]interface{})
	return len(keys)
}

// TestVault_FastPathRotationRemintsWithoutStaging is the row nothing in the repo
// covers today: a rotation actually completing, observed from both ends.
//
// The two-stage design splits rotation into prepare and activate, and lets a
// driver ask for a delay between them for upstreams that need one to converge.
// Vault needs none, so its prepare reports a zero delay and the whole rotation
// finishes inside one job. That is the branch under test, and last_rotation is
// what distinguishes it: the delayed path parks the entry in a staged state and
// leaves last_rotation unset until a second job runs, so a stamped last_rotation
// can only mean prepare and activate both completed.
//
// Then the harder half. Rotation replaces the secret the source authenticates
// with, so the interesting failure is not the rotation reporting success — it is
// the source being unable to log in afterwards, which would surface much later as
// a mint failure on somebody else's request. A fresh session minting a usable
// token after the rotation is what rules that out.
func TestVault_FastPathRotationRemintsWithoutStaging(t *testing.T) {
	ensureEnv(t)
	setupVaultRotationEnv(t)

	// Before: the chain works, and the source holds whatever secret_ids it was
	// created with.
	status, body, _ := h.ChainRequest(t, leaderPort, vaultEnv, h.ChainOpts{
		AgentCertPEM: agentCert(t),
		Bearer:       h.FullChainUserJWT(t),
		Role:         vaultRotAgentRole,
	})
	h.AssertChain(t, upstream, status, body, h.ChainWant{
		Status:        200,
		Absent:        h.AlwaysAbsent("Authorization"),
		UpstreamCalls: 1,
	})
	assertVaultTokenUsable(t, mintedVaultToken(t))
	accessorsBefore := vaultSecretIDCount(t, vaultRotApproleRole)

	// last_rotation is absent until one completes, so this waits for the field to
	// appear rather than for a value to change.
	deadline := time.Now().Add(90 * time.Second)
	rotated := false
	for time.Now().Before(deadline) {
		readStatus, readBody := h.APIRequest(t, "GET", "sys/cred/sources/"+vaultRotSource, leaderPort, "")
		if readStatus == 200 {
			if last, _ := h.JSONPath(h.ParseJSON(t, readBody), "data.last_rotation").(string); last != "" {
				rotated = true
				break
			}
		}
		time.Sleep(2 * time.Second)
	}
	if !rotated {
		t.Fatalf("source %s never recorded a completed rotation within the deadline", vaultRotSource)
	}

	// A new certificate and a new user token, so nothing about this request can be
	// served from the session the first one established.
	upstream.Reset()
	afterStatus, afterBody, _ := h.ChainRequest(t, leaderPort, vaultEnv, h.ChainOpts{
		AgentCertPEM: agentCert(t),
		Bearer:       h.FullChainUserJWT(t),
		Role:         vaultRotAgentRole,
	})
	h.AssertChain(t, upstream, afterStatus, afterBody, h.ChainWant{
		Status:        200,
		Absent:        h.AlwaysAbsent("Authorization"),
		UpstreamCalls: 1,
	})
	assertVaultTokenUsable(t, mintedVaultToken(t))

	// Growth rather than replacement, deliberately. The first cycle has no prior
	// accessor to clean up — the source was created from a secret_id registered by
	// hand, so nothing recorded the accessor that would have been destroyed — and
	// cleanup on an empty accessor does nothing. Asserting a replacement would be
	// asserting behaviour the first cycle does not have.
	if after := vaultSecretIDCount(t, vaultRotApproleRole); after <= accessorsBefore {
		t.Errorf("AppRole role %s holds %d secret_id accessors, want more than the %d it held before rotating",
			vaultRotApproleRole, after, accessorsBefore)
	}
}
