package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSys_CreateCredentialSource(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/v1/sys/cred/sources/my-src" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data":{"name":"my-src","type":"vault","message":"created","config":{"addr":"http://localhost:8200"},"rotation_period":3600}}`))
	}))
	defer server.Close()

	config := DefaultConfig()
	config.Address = server.URL
	client, _ := NewClient(config)

	out, err := client.Sys().CreateCredentialSource("my-src", &CreateCredentialSourceInput{
		Type:           "vault",
		Config:         map[string]string{"addr": "http://localhost:8200"},
		RotationPeriod: time.Hour,
	})
	if err != nil {
		t.Fatalf("CreateCredentialSource failed: %v", err)
	}
	if out.Name != "my-src" {
		t.Errorf("expected name my-src, got %s", out.Name)
	}
	if out.Type != "vault" {
		t.Errorf("expected type vault, got %s", out.Type)
	}
	if out.RotationPeriod != time.Hour {
		t.Errorf("expected rotation_period 1h, got %v", out.RotationPeriod)
	}
	if out.Config["addr"] != "http://localhost:8200" {
		t.Errorf("unexpected config: %v", out.Config)
	}
}

func TestSys_CreateCredentialSource_NilInput(t *testing.T) {
	config := DefaultConfig()
	config.Address = "http://127.0.0.1:1"
	client, _ := NewClient(config)

	_, err := client.Sys().CreateCredentialSource("test", nil)
	if err == nil {
		t.Fatal("expected error for nil input")
	}
}

func TestSys_CreateCredentialSource_MarshalJSON(t *testing.T) {
	input := CreateCredentialSourceInput{
		Type:           "aws",
		Config:         map[string]string{"region": "us-east-1"},
		RotationPeriod: 30 * time.Minute,
	}
	data, err := input.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON failed: %v", err)
	}
	s := string(data)
	if s == "" {
		t.Fatal("expected non-empty JSON")
	}
}

func TestSys_GetCredentialSource(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data":{"name":"my-src","type":"vault","config":{"addr":"http://localhost:8200"},"rotation_period":7200,"next_rotation":"2026-01-01T00:00:00Z","last_rotation":"2025-12-31T00:00:00Z"}}`))
	}))
	defer server.Close()

	config := DefaultConfig()
	config.Address = server.URL
	client, _ := NewClient(config)

	out, err := client.Sys().GetCredentialSource("my-src")
	if err != nil {
		t.Fatalf("GetCredentialSource failed: %v", err)
	}
	if out.Name != "my-src" {
		t.Errorf("expected name my-src, got %s", out.Name)
	}
	if out.RotationPeriod != 2*time.Hour {
		t.Errorf("expected 2h, got %v", out.RotationPeriod)
	}
	if out.NextRotation != "2026-01-01T00:00:00Z" {
		t.Errorf("unexpected next_rotation: %s", out.NextRotation)
	}
	if out.LastRotation != "2025-12-31T00:00:00Z" {
		t.Errorf("unexpected last_rotation: %s", out.LastRotation)
	}
}

func TestSys_ListCredentialSources(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("warden-list") != "true" {
			t.Error("expected warden-list=true")
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data":{"sources":[{"name":"s1","type":"vault","rotation_period":3600},{"name":"s2","type":"aws","config":{"region":"us-east-1"},"rotation_period":1800}]}}`))
	}))
	defer server.Close()

	config := DefaultConfig()
	config.Address = server.URL
	client, _ := NewClient(config)

	sources, err := client.Sys().ListCredentialSources()
	if err != nil {
		t.Fatalf("ListCredentialSources failed: %v", err)
	}
	if len(sources) != 2 {
		t.Fatalf("expected 2 sources, got %d", len(sources))
	}
	if sources[0].Name != "s1" {
		t.Errorf("expected s1, got %s", sources[0].Name)
	}
	if sources[1].Config["region"] != "us-east-1" {
		t.Errorf("unexpected config: %v", sources[1].Config)
	}
}

func TestSys_ListCredentialSources_Empty(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data":{}}`))
	}))
	defer server.Close()

	config := DefaultConfig()
	config.Address = server.URL
	client, _ := NewClient(config)

	sources, err := client.Sys().ListCredentialSources()
	if err != nil {
		t.Fatalf("ListCredentialSources failed: %v", err)
	}
	if len(sources) != 0 {
		t.Errorf("expected empty, got %d", len(sources))
	}
}

func TestSys_UpdateCredentialSource(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Errorf("expected PUT, got %s", r.Method)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data":{"name":"my-src","message":"updated"}}`))
	}))
	defer server.Close()

	config := DefaultConfig()
	config.Address = server.URL
	client, _ := NewClient(config)

	out, err := client.Sys().UpdateCredentialSource("my-src", &UpdateCredentialSourceInput{
		Config: map[string]string{"addr": "http://new:8200"},
	})
	if err != nil {
		t.Fatalf("UpdateCredentialSource failed: %v", err)
	}
	if out.Name != "my-src" {
		t.Errorf("expected name my-src, got %s", out.Name)
	}
	if out.Message != "updated" {
		t.Errorf("unexpected message: %s", out.Message)
	}
}

func TestSys_UpdateCredentialSource_NilInput(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data":{"name":"my-src","message":"ok"}}`))
	}))
	defer server.Close()

	config := DefaultConfig()
	config.Address = server.URL
	client, _ := NewClient(config)

	_, err := client.Sys().UpdateCredentialSource("my-src", nil)
	if err != nil {
		t.Fatalf("UpdateCredentialSource nil input failed: %v", err)
	}
}

func TestSys_DeleteCredentialSource(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Errorf("expected DELETE, got %s", r.Method)
		}
		if r.URL.Path != "/v1/sys/cred/sources/my-src" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	config := DefaultConfig()
	config.Address = server.URL
	client, _ := NewClient(config)

	err := client.Sys().DeleteCredentialSource("my-src")
	if err != nil {
		t.Fatalf("DeleteCredentialSource failed: %v", err)
	}
}
