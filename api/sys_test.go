package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSys_Init(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/v1/sys/init" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data":{"root_token":"s.root123","keys":["key1","key2"],"keys_base64":["a2V5MQ==","a2V5Mg=="],"recovery_keys":["rk1"],"recovery_keys_base64":["cmsx"]}}`))
	}))
	defer server.Close()

	config := DefaultConfig()
	config.Address = server.URL
	client, _ := NewClient(config)

	resp, err := client.Sys().Init()
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	if resp.RootToken != "s.root123" {
		t.Errorf("expected root token s.root123, got %s", resp.RootToken)
	}
	if len(resp.Keys) != 2 {
		t.Errorf("expected 2 keys, got %d", len(resp.Keys))
	}
	if len(resp.KeysBase64) != 2 {
		t.Errorf("expected 2 keys_base64, got %d", len(resp.KeysBase64))
	}
	if len(resp.RecoveryKeys) != 1 {
		t.Errorf("expected 1 recovery key, got %d", len(resp.RecoveryKeys))
	}
	if len(resp.RecoveryKeysBase64) != 1 {
		t.Errorf("expected 1 recovery_keys_base64, got %d", len(resp.RecoveryKeysBase64))
	}
}

func TestSys_InitWithRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data":{"root_token":"s.custom","keys":["k1"]}}`))
	}))
	defer server.Close()

	config := DefaultConfig()
	config.Address = server.URL
	client, _ := NewClient(config)

	resp, err := client.Sys().InitWithRequest(&InitRequest{
		SecretShares:    5,
		SecretThreshold: 3,
	})
	if err != nil {
		t.Fatalf("InitWithRequest failed: %v", err)
	}
	if resp.RootToken != "s.custom" {
		t.Errorf("expected s.custom, got %s", resp.RootToken)
	}
}

func TestSys_Health_Active(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}
		if r.URL.Path != "/v1/sys/health" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"initialized":true,"sealed":false,"standby":false,"ha_enabled":true,"is_leader":true,"leader_address":"https://leader:8200","active_time":"2026-05-22T18:03:11Z","version":"0.4.2","server_time":"2026-05-23T14:34:22Z"}`))
	}))
	defer server.Close()

	config := DefaultConfig()
	config.Address = server.URL
	client, _ := NewClient(config)

	resp, err := client.Sys().Health()
	if err != nil {
		t.Fatalf("Health failed: %v", err)
	}
	if !resp.Initialized || resp.Sealed || resp.Standby {
		t.Errorf("expected active node, got initialized=%v sealed=%v standby=%v", resp.Initialized, resp.Sealed, resp.Standby)
	}
	if !resp.HAEnabled || !resp.IsLeader {
		t.Errorf("expected HA leader, got ha_enabled=%v is_leader=%v", resp.HAEnabled, resp.IsLeader)
	}
	if resp.LeaderAddress != "https://leader:8200" {
		t.Errorf("leader_address = %q", resp.LeaderAddress)
	}
	if resp.Version != "0.4.2" {
		t.Errorf("version = %q", resp.Version)
	}
	if resp.ServerTime != "2026-05-23T14:34:22Z" {
		t.Errorf("server_time = %q", resp.ServerTime)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d; want 200", resp.StatusCode)
	}
}

func TestSys_Health_StandbyReturns429(t *testing.T) {
	// Standby case: ha_enabled=true, is_leader=false. Critical that
	// is_leader is emitted as a literal `false` and not silently dropped.
	// Otherwise the consumer can't distinguish "HA on, this is a standby"
	// from "HA off entirely".
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		w.Write([]byte(`{"initialized":true,"sealed":false,"standby":true,"ha_enabled":true,"is_leader":false,"leader_address":"https://leader:8200","server_time":"2026-05-23T14:34:22Z"}`))
	}))
	defer server.Close()

	config := DefaultConfig()
	config.Address = server.URL
	client, _ := NewClient(config)

	resp, err := client.Sys().Health()
	if err != nil {
		t.Fatalf("Health on standby (429) should not error, got %v", err)
	}
	if !resp.Standby || resp.IsLeader {
		t.Errorf("expected standby node, got standby=%v is_leader=%v", resp.Standby, resp.IsLeader)
	}
	if !resp.HAEnabled {
		t.Errorf("standby case must surface ha_enabled=true; got false")
	}
	if resp.LeaderAddress != "https://leader:8200" {
		t.Errorf("leader_address = %q; want https://leader:8200", resp.LeaderAddress)
	}
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("StatusCode = %d; want 429", resp.StatusCode)
	}
}

func TestSys_Health_SealedReturns503(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte(`{"initialized":true,"sealed":true,"standby":false,"ha_enabled":true,"server_time":"2026-05-23T14:34:22Z"}`))
	}))
	defer server.Close()

	config := DefaultConfig()
	config.Address = server.URL
	client, _ := NewClient(config)

	resp, err := client.Sys().Health()
	if err != nil {
		t.Fatalf("Health on sealed (503) should not error, got %v", err)
	}
	if !resp.Sealed {
		t.Errorf("expected sealed=true")
	}
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("StatusCode = %d; want 503", resp.StatusCode)
	}
}

func TestSys_Health_UninitializedReturns501(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotImplemented)
		w.Write([]byte(`{"initialized":false,"sealed":true,"standby":false,"ha_enabled":false,"server_time":"2026-05-23T14:34:22Z"}`))
	}))
	defer server.Close()

	config := DefaultConfig()
	config.Address = server.URL
	client, _ := NewClient(config)

	resp, err := client.Sys().Health()
	if err != nil {
		t.Fatalf("Health on uninitialized (501) should not error, got %v", err)
	}
	if resp.Initialized {
		t.Errorf("expected initialized=false")
	}
	if resp.StatusCode != http.StatusNotImplemented {
		t.Errorf("StatusCode = %d; want 501", resp.StatusCode)
	}
}

func TestSys_RevokeRootToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/v1/sys/revoke-root-token" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	config := DefaultConfig()
	config.Address = server.URL
	client, _ := NewClient(config)

	err := client.Sys().RevokeRootToken()
	if err != nil {
		t.Fatalf("RevokeRootToken failed: %v", err)
	}
}
