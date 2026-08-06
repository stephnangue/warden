//go:build e2e

// Package oidc_signer exercises the OIDC issuer's external signer (remote signing):
// the private signing key lives in Vault transit and never leaves it. It proves the
// keys are provisioned in transit and are non-exportable, and that an HA promotion
// serves the same JWKS without moving any key material (the promoted node just
// points at the same transit keys).
package oidc_signer

import (
	"encoding/json"
	"testing"
	"time"

	h "github.com/stephnangue/warden/e2e/helpers"
)

const (
	vaultAddr  = "http://127.0.0.1:8200"
	vaultToken = "e2e-vault-root-token"
)

// jwksActiveKids fetches the issuer JWKS from a node origin and returns the active
// (first-listed) kid per algorithm.
func jwksActiveKids(t *testing.T, port int) map[string]string {
	t.Helper()
	status, body := h.DoRequest(t, "GET", h.NodeURL(port)+"/oidc/jwks", nil, "")
	if status != 200 {
		t.Fatalf("GET /oidc/jwks on :%d = %d: %s", port, status, body)
	}
	var doc struct {
		Keys []struct {
			Kid string `json:"kid"`
			Alg string `json:"alg"`
			Use string `json:"use"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("parse jwks: %v (%s)", err, body)
	}
	kids := map[string]string{}
	for _, k := range doc.Keys {
		if k.Use != "sig" {
			t.Errorf("jwk %s has use=%q, want sig", k.Kid, k.Use)
		}
		// JWKS lists active, then next, then retired per alg; keep the active (first).
		if _, ok := kids[k.Alg]; !ok {
			kids[k.Alg] = k.Kid
		}
	}
	return kids
}

// waitForIssuerReady polls the JWKS until both supported algorithms are published.
func waitForIssuerReady(t *testing.T, port int) map[string]string {
	t.Helper()
	for attempt := 0; attempt < 30; attempt++ {
		kids := jwksActiveKids(t, port)
		if kids["RS256"] != "" && kids["ES256"] != "" {
			return kids
		}
		time.Sleep(time.Second)
	}
	t.Fatalf("issuer never became ready on :%d", port)
	return nil
}

func TestOIDCSigner_RemoteTransit_And_HAPromotion(t *testing.T) {
	leader := h.GetLeaderPort(t)

	// 1. Enable the issuer on the active node. With the signer "transit" stanza in
	//    each node's config, this provisions the signing keys IN transit — the
	//    private key is created there and never enters Warden.
	body := `{"enabled":true,"issuer_url":"` + h.NodeURL(leader) + `","key_rotation_period":0}`
	if status, resp := h.APIRequest(t, "POST", "sys/oidc-issuer/config", leader, body); status != 200 {
		t.Fatalf("enable issuer = %d: %s", status, resp)
	}
	kids := waitForIssuerReady(t, leader)

	// 2. Prove remote signing: the transit keys exist and are NON-EXPORTABLE. If the
	//    issuer were using local in-process keys, these transit keys would not exist.
	for _, alg := range []string{"rs256", "es256"} {
		name := "warden-oidc-" + alg
		st, kb := h.DoRequest(t, "GET", vaultAddr+"/v1/transit/keys/"+name,
			map[string]string{"X-Vault-Token": vaultToken}, "")
		if st != 200 {
			t.Fatalf("transit key %s missing (status %d): %s — remote signing not in use", name, st, kb)
		}
		if h.JSONBool(t, kb, "data.exportable") {
			t.Errorf("transit key %s is exportable; the issuer key must never be extractable", name)
		}
		// Transit must refuse to export the signing key material.
		if est, _ := h.DoRequest(t, "GET", vaultAddr+"/v1/transit/export/signing-key/"+name,
			map[string]string{"X-Vault-Token": vaultToken}, ""); est == 200 {
			t.Errorf("transit allowed exporting %s; the key must be non-exportable", name)
		}
	}

	// 3. HA: kill the active node. A standby promotes and serves the SAME JWKS kids,
	//    proving promotion needs NO key material — the new leader reconstructs the
	//    handles from storage and points at the same transit keys.
	leaderNode := h.NodeNumberForPort(leader)
	h.KillNode(t, leaderNode, "TERM")
	t.Cleanup(func() { h.RestartNode(t, leaderNode) })

	newLeader := h.WaitForLeader(t, 30, time.Second)
	if newLeader == 0 || newLeader == leader {
		t.Fatalf("no new leader after killing :%d (got :%d)", leader, newLeader)
	}

	promoted := waitForIssuerReady(t, newLeader)
	if promoted["RS256"] != kids["RS256"] || promoted["ES256"] != kids["ES256"] {
		t.Fatalf("JWKS kids changed across promotion: before=%v after=%v (key material must not move)", kids, promoted)
	}
}
