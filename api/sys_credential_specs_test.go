package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSys_CreateCredentialSpec(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/v1/sys/cred/specs/my-spec" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data":{"name":"my-spec","type":"kv","source":"my-src","message":"created","config":{"key":"val"},"min_ttl":300,"max_ttl":3600,"rotation_period":1800}}`))
	}))
	defer server.Close()

	config := DefaultConfig()
	config.Address = server.URL
	client, _ := NewClient(config)

	out, err := client.Sys().CreateCredentialSpec("my-spec", &CreateCredentialSpecInput{
		Type:           "kv",
		Source:         "my-src",
		Config:         map[string]string{"key": "val"},
		MinTTL:         5 * time.Minute,
		MaxTTL:         time.Hour,
		RotationPeriod: 30 * time.Minute,
	})
	if err != nil {
		t.Fatalf("CreateCredentialSpec failed: %v", err)
	}
	if out.Name != "my-spec" {
		t.Errorf("expected name my-spec, got %s", out.Name)
	}
	if out.Type != "kv" {
		t.Errorf("expected type kv, got %s", out.Type)
	}
	if out.Source != "my-src" {
		t.Errorf("expected source my-src, got %s", out.Source)
	}
	if out.MinTTL != 5*time.Minute {
		t.Errorf("expected min_ttl 5m, got %v", out.MinTTL)
	}
	if out.MaxTTL != time.Hour {
		t.Errorf("expected max_ttl 1h, got %v", out.MaxTTL)
	}
	if out.RotationPeriod != 30*time.Minute {
		t.Errorf("expected rotation_period 30m, got %v", out.RotationPeriod)
	}
}

func TestSys_CreateCredentialSpec_NilInput(t *testing.T) {
	config := DefaultConfig()
	config.Address = "http://127.0.0.1:1"
	client, _ := NewClient(config)

	_, err := client.Sys().CreateCredentialSpec("test", nil)
	if err == nil {
		t.Fatal("expected error for nil input")
	}
}

func TestSys_GetCredentialSpec(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data":{"name":"my-spec","type":"kv","source":"my-src","config":{"key":"val"},"min_ttl":60,"max_ttl":120,"rotation_period":300}}`))
	}))
	defer server.Close()

	config := DefaultConfig()
	config.Address = server.URL
	client, _ := NewClient(config)

	out, err := client.Sys().GetCredentialSpec("my-spec")
	if err != nil {
		t.Fatalf("GetCredentialSpec failed: %v", err)
	}
	if out.Name != "my-spec" {
		t.Errorf("expected my-spec, got %s", out.Name)
	}
	if out.MinTTL != time.Minute {
		t.Errorf("expected 1m, got %v", out.MinTTL)
	}
	if out.MaxTTL != 2*time.Minute {
		t.Errorf("expected 2m, got %v", out.MaxTTL)
	}
	if out.RotationPeriod != 5*time.Minute {
		t.Errorf("expected 5m, got %v", out.RotationPeriod)
	}
}

func TestSys_ListCredentialSpecs(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("warden-list") != "true" {
			t.Error("expected warden-list=true")
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data":{"specs":[{"name":"s1","type":"kv","source":"src1","min_ttl":60,"max_ttl":120},{"name":"s2","type":"db","source":"src2","config":{"db":"pg"},"min_ttl":30,"max_ttl":60,"rotation_period":600}]}}`))
	}))
	defer server.Close()

	config := DefaultConfig()
	config.Address = server.URL
	client, _ := NewClient(config)

	specs, err := client.Sys().ListCredentialSpecs()
	if err != nil {
		t.Fatalf("ListCredentialSpecs failed: %v", err)
	}
	if len(specs) != 2 {
		t.Fatalf("expected 2 specs, got %d", len(specs))
	}
	if specs[0].Name != "s1" {
		t.Errorf("expected s1, got %s", specs[0].Name)
	}
	if specs[1].Config["db"] != "pg" {
		t.Errorf("unexpected config: %v", specs[1].Config)
	}
	if specs[1].RotationPeriod != 10*time.Minute {
		t.Errorf("expected 10m, got %v", specs[1].RotationPeriod)
	}
}

func TestSys_ListCredentialSpecs_Empty(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data":{}}`))
	}))
	defer server.Close()

	config := DefaultConfig()
	config.Address = server.URL
	client, _ := NewClient(config)

	specs, err := client.Sys().ListCredentialSpecs()
	if err != nil {
		t.Fatalf("failed: %v", err)
	}
	if len(specs) != 0 {
		t.Errorf("expected empty, got %d", len(specs))
	}
}

func TestSys_UpdateCredentialSpec(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Errorf("expected PUT, got %s", r.Method)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data":{"name":"my-spec","message":"updated"}}`))
	}))
	defer server.Close()

	config := DefaultConfig()
	config.Address = server.URL
	client, _ := NewClient(config)

	minTTL := 2 * time.Minute
	maxTTL := 10 * time.Minute
	rp := 5 * time.Minute
	out, err := client.Sys().UpdateCredentialSpec("my-spec", &UpdateCredentialSpecInput{
		Config:         map[string]string{"key": "new"},
		MinTTL:         &minTTL,
		MaxTTL:         &maxTTL,
		RotationPeriod: &rp,
	})
	if err != nil {
		t.Fatalf("UpdateCredentialSpec failed: %v", err)
	}
	if out.Name != "my-spec" {
		t.Errorf("expected my-spec, got %s", out.Name)
	}
	if out.Message != "updated" {
		t.Errorf("unexpected message: %s", out.Message)
	}
}

func TestSys_UpdateCredentialSpec_NilInput(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data":{"name":"my-spec","message":"ok"}}`))
	}))
	defer server.Close()

	config := DefaultConfig()
	config.Address = server.URL
	client, _ := NewClient(config)

	_, err := client.Sys().UpdateCredentialSpec("my-spec", nil)
	if err != nil {
		t.Fatalf("failed: %v", err)
	}
}

func TestSys_DeleteCredentialSpec(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Errorf("expected DELETE, got %s", r.Method)
		}
		if r.URL.Path != "/v1/sys/cred/specs/my-spec" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	config := DefaultConfig()
	config.Address = server.URL
	client, _ := NewClient(config)

	err := client.Sys().DeleteCredentialSpec("my-spec")
	if err != nil {
		t.Fatalf("DeleteCredentialSpec failed: %v", err)
	}
}
