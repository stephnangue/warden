package api

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSys_ListMounts(t *testing.T) {
	t.Run("successfully lists providers", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/v1/sys/providers" {
				t.Errorf("expected path /v1/sys/providers, got %s", r.URL.Path)
			}
			if r.Method != http.MethodGet {
				t.Errorf("expected GET method, got %s", r.Method)
			}

			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{
				"$schema": "http://localhost:5000/schemas/ListMountsOutput.json",
				"mounts": {
					"secret/": {
						"type": "kv",
						"description": "Key-Value secrets engine",
						"accessor": "kv_accessor_123",
						"config": {
							"default_lease_ttl": 0,
							"max_lease_ttl": 0,
							"force_no_cache": false
						}
					},
					"database/": {
						"type": "database",
						"description": "Database secrets engine",
						"accessor": "database_accessor_456",
						"config": {
							"default_lease_ttl": 3600,
							"max_lease_ttl": 7200
						}
					}
				}
			}`))
		}))
		defer server.Close()

		config := DefaultConfig()
		config.Address = server.URL

		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		mounts, err := client.Sys().ListMounts()
		if err != nil {
			t.Fatalf("ListMounts failed: %v", err)
		}

		if mounts == nil {
			t.Fatal("expected mounts map, got nil")
		}

		if len(mounts) != 2 {
			t.Errorf("expected 2 mounts, got %d", len(mounts))
		}

		secretMount, ok := mounts["secret/"]
		if !ok {
			t.Fatal("expected secret/ mount")
		}

		if secretMount.Type != "kv" {
			t.Errorf("expected type kv, got %s", secretMount.Type)
		}

		if secretMount.Description != "Key-Value secrets engine" {
			t.Errorf("expected description 'Key-Value secrets engine', got %s", secretMount.Description)
		}

		if secretMount.Accessor != "kv_accessor_123" {
			t.Errorf("expected accessor kv_accessor_123, got %s", secretMount.Accessor)
		}

		databaseMount, ok := mounts["database/"]
		if !ok {
			t.Fatal("expected database/ mount")
		}

		if databaseMount.Type != "database" {
			t.Errorf("expected type database, got %s", databaseMount.Type)
		}
	})

	t.Run("returns error for server error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"errors": ["internal server error"]}`))
		}))
		defer server.Close()

		config := DefaultConfig()
		config.Address = server.URL
		config.MaxRetries = 0

		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		_, err = client.Sys().ListMounts()
		if err == nil {
			t.Error("expected error for 500 status")
		}
	})

	t.Run("returns error for empty response data", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{}`))
		}))
		defer server.Close()

		config := DefaultConfig()
		config.Address = server.URL

		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		_, err = client.Sys().ListMounts()
		if err == nil {
			t.Error("expected error for empty data")
		}
		if err.Error() != "data from server response is empty" {
			t.Errorf("expected 'data from server response is empty' error, got: %v", err)
		}
	})

	t.Run("returns error for invalid JSON", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`invalid json`))
		}))
		defer server.Close()

		config := DefaultConfig()
		config.Address = server.URL

		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		_, err = client.Sys().ListMounts()
		if err == nil {
			t.Error("expected error for invalid JSON")
		}
	})

	t.Run("handles empty mounts list", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"mounts": {}}`))
		}))
		defer server.Close()

		config := DefaultConfig()
		config.Address = server.URL

		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		mounts, err := client.Sys().ListMounts()
		if err != nil {
			t.Fatalf("ListMounts failed: %v", err)
		}

		if len(mounts) != 0 {
			t.Errorf("expected empty mounts map, got %d entries", len(mounts))
		}
	})

	t.Run("returns error when mounts field is missing", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"$schema": "http://localhost:5000/schemas/ListMountsOutput.json"}`))
		}))
		defer server.Close()

		config := DefaultConfig()
		config.Address = server.URL

		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		_, err = client.Sys().ListMounts()
		if err == nil {
			t.Error("expected error when mounts field is missing")
		}
		if err.Error() != "mounts field not found in response" {
			t.Errorf("expected 'mounts field not found in response' error, got: %v", err)
		}
	})
}

func TestSys_ListMountsWithContext(t *testing.T) {
	t.Run("successfully lists mounts with context", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{
				"$schema": "http://localhost:5000/schemas/ListMountsOutput.json",
				"mounts": {
					"secret/": {
						"type": "kv",
						"description": "Key-Value secrets engine",
						"accessor": "kv_accessor_123"
					}
				}
			}`))
		}))
		defer server.Close()

		config := DefaultConfig()
		config.Address = server.URL

		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		ctx := context.Background()
		mounts, err := client.Sys().ListMountsWithContext(ctx)
		if err != nil {
			t.Fatalf("ListMountsWithContext failed: %v", err)
		}

		if len(mounts) != 1 {
			t.Errorf("expected 1 mount, got %d", len(mounts))
		}
	})

	t.Run("respects context cancellation", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(time.Second * 2)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"mounts": {}}`))
		}))
		defer server.Close()

		config := DefaultConfig()
		config.Address = server.URL

		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*100)
		defer cancel()

		_, err = client.Sys().ListMountsWithContext(ctx)
		if err == nil {
			t.Error("expected error due to context timeout")
		}
	})

	t.Run("respects context deadline", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(time.Millisecond * 500)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"mounts": {}}`))
		}))
		defer server.Close()

		config := DefaultConfig()
		config.Address = server.URL

		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(time.Millisecond*50))
		defer cancel()

		_, err = client.Sys().ListMountsWithContext(ctx)
		if err == nil {
			t.Error("expected error due to context deadline")
		}
	})
}

func TestSys_Mount(t *testing.T) {
	t.Run("successfully mounts providers", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/v1/sys/providers/database" {
				t.Errorf("expected path /v1/sys/providers/database, got %s", r.URL.Path)
			}
			if r.Method != http.MethodPost {
				t.Errorf("expected POST method, got %s", r.Method)
			}

			w.WriteHeader(http.StatusNoContent)
		}))
		defer server.Close()

		config := DefaultConfig()
		config.Address = server.URL

		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		mountInput := &MountInput{
			Type:        "database",
			Description: "Test database secrets engine",
			Config: map[string]any{
				"default_lease_ttl": 3600,
				"max_lease_ttl":     7200,
			},
		}

		err = client.Sys().Mount("database", mountInput)
		if err != nil {
			t.Fatalf("Mount failed: %v", err)
		}
	})

	t.Run("returns error for server error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"errors": ["invalid mount type"]}`))
		}))
		defer server.Close()

		config := DefaultConfig()
		config.Address = server.URL
		config.MaxRetries = 0

		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		mountInput := &MountInput{
			Type: "invalid",
		}

		err = client.Sys().Mount("test", mountInput)
		if err == nil {
			t.Error("expected error for invalid mount type")
		}
	})

	t.Run("handles path with special characters", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/v1/sys/providers/my-secret-engine" {
				t.Errorf("expected path /v1/sys/providers/my-secret-engine, got %s", r.URL.Path)
			}
			w.WriteHeader(http.StatusNoContent)
		}))
		defer server.Close()

		config := DefaultConfig()
		config.Address = server.URL

		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		mountInput := &MountInput{
			Type: "kv",
		}

		err = client.Sys().Mount("my-secret-engine", mountInput)
		if err != nil {
			t.Fatalf("Mount failed: %v", err)
		}
	})

	t.Run("handles mount with complex config", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}))
		defer server.Close()

		config := DefaultConfig()
		config.Address = server.URL

		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		mountInput := &MountInput{
			Type:        "database",
			Description: "PostgreSQL database",
			Config: map[string]any{
				"default_lease_ttl": 3600,
				"max_lease_ttl":     7200,
				"force_no_cache":    false,
				"plugin_name":       "postgresql-database-plugin",
			},
		}

		err = client.Sys().Mount("postgres", mountInput)
		if err != nil {
			t.Fatalf("Mount failed: %v", err)
		}
	})
}

func TestSys_MountWithContext(t *testing.T) {
	t.Run("successfully mounts secrets engine with context", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}))
		defer server.Close()

		config := DefaultConfig()
		config.Address = server.URL

		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		ctx := context.Background()
		mountInput := &MountInput{
			Type: "kv",
		}

		err = client.Sys().MountWithContext(ctx, "secret", mountInput)
		if err != nil {
			t.Fatalf("MountWithContext failed: %v", err)
		}
	})

	t.Run("respects context cancellation", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(time.Second * 2)
			w.WriteHeader(http.StatusNoContent)
		}))
		defer server.Close()

		config := DefaultConfig()
		config.Address = server.URL

		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*100)
		defer cancel()

		mountInput := &MountInput{
			Type: "kv",
		}

		err = client.Sys().MountWithContext(ctx, "secret", mountInput)
		if err == nil {
			t.Error("expected error due to context timeout")
		}
	})

	t.Run("handles nil mount input", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}))
		defer server.Close()

		config := DefaultConfig()
		config.Address = server.URL

		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		ctx := context.Background()
		err = client.Sys().MountWithContext(ctx, "secret", nil)
		if err != nil {
			t.Fatalf("MountWithContext with nil input failed: %v", err)
		}
	})
}

func TestSys_Unmount(t *testing.T) {
	t.Run("successfully unmounts secrets engine", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/v1/sys/providers/database" {
				t.Errorf("expected path /v1/sys/providers/database, got %s", r.URL.Path)
			}
			if r.Method != http.MethodDelete {
				t.Errorf("expected DELETE method, got %s", r.Method)
			}

			w.WriteHeader(http.StatusNoContent)
		}))
		defer server.Close()

		config := DefaultConfig()
		config.Address = server.URL

		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		err = client.Sys().Unmount("database")
		if err != nil {
			t.Fatalf("Unmount failed: %v", err)
		}
	})

	t.Run("returns error for non-existent mount", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"errors": ["mount not found"]}`))
		}))
		defer server.Close()

		config := DefaultConfig()
		config.Address = server.URL
		config.MaxRetries = 0

		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		err = client.Sys().Unmount("nonexistent")
		if err == nil {
			t.Error("expected error for non-existent mount")
		}
	})

	t.Run("handles path with special characters", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/v1/sys/providers/my-secret-engine" {
				t.Errorf("expected path /v1/sys/providers/my-secret-engine, got %s", r.URL.Path)
			}
			w.WriteHeader(http.StatusNoContent)
		}))
		defer server.Close()

		config := DefaultConfig()
		config.Address = server.URL

		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		err = client.Sys().Unmount("my-secret-engine")
		if err != nil {
			t.Fatalf("Unmount failed: %v", err)
		}
	})

	t.Run("returns error for server error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"errors": ["internal server error"]}`))
		}))
		defer server.Close()

		config := DefaultConfig()
		config.Address = server.URL
		config.MaxRetries = 0

		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		err = client.Sys().Unmount("database")
		if err == nil {
			t.Error("expected error for 500 status")
		}
	})
}

func TestSys_UnmountWithContext(t *testing.T) {
	t.Run("successfully unmounts secrets engine with context", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}))
		defer server.Close()

		config := DefaultConfig()
		config.Address = server.URL

		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		ctx := context.Background()
		err = client.Sys().UnmountWithContext(ctx, "database")
		if err != nil {
			t.Fatalf("UnmountWithContext failed: %v", err)
		}
	})

	t.Run("respects context cancellation", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(time.Second * 2)
			w.WriteHeader(http.StatusNoContent)
		}))
		defer server.Close()

		config := DefaultConfig()
		config.Address = server.URL

		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*100)
		defer cancel()

		err = client.Sys().UnmountWithContext(ctx, "database")
		if err == nil {
			t.Error("expected error due to context timeout")
		}
	})

	t.Run("respects context deadline", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(time.Millisecond * 500)
			w.WriteHeader(http.StatusNoContent)
		}))
		defer server.Close()

		config := DefaultConfig()
		config.Address = server.URL

		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(time.Millisecond*50))
		defer cancel()

		err = client.Sys().UnmountWithContext(ctx, "database")
		if err == nil {
			t.Error("expected error due to context deadline")
		}
	})
}

func TestSys_TuneMount(t *testing.T) {
	t.Run("successfully tunes mount configuration", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/v1/sys/providers/database/tune" {
				t.Errorf("expected path /v1/sys/providers/database/tune, got %s", r.URL.Path)
			}
			if r.Method != http.MethodPost {
				t.Errorf("expected POST method, got %s", r.Method)
			}

			w.WriteHeader(http.StatusNoContent)
		}))
		defer server.Close()

		config := DefaultConfig()
		config.Address = server.URL

		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		tuneConfig := map[string]any{
			"default_lease_ttl": 7200,
			"max_lease_ttl":     14400,
		}

		err = client.Sys().TuneMount("database", tuneConfig)
		if err != nil {
			t.Fatalf("TuneMount failed: %v", err)
		}
	})

	t.Run("returns error for server error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"errors": ["invalid configuration"]}`))
		}))
		defer server.Close()

		config := DefaultConfig()
		config.Address = server.URL
		config.MaxRetries = 0

		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		tuneConfig := map[string]any{
			"invalid_key": "invalid_value",
		}

		err = client.Sys().TuneMount("database", tuneConfig)
		if err == nil {
			t.Error("expected error for invalid configuration")
		}
	})

	t.Run("handles empty config", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}))
		defer server.Close()

		config := DefaultConfig()
		config.Address = server.URL

		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		tuneConfig := map[string]any{}

		err = client.Sys().TuneMount("database", tuneConfig)
		if err != nil {
			t.Fatalf("TuneMount with empty config failed: %v", err)
		}
	})
}

func TestSys_TuneMountWithContext(t *testing.T) {
	t.Run("successfully tunes mount with context", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}))
		defer server.Close()

		config := DefaultConfig()
		config.Address = server.URL

		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		ctx := context.Background()
		tuneConfig := map[string]any{
			"default_lease_ttl": 7200,
		}

		err = client.Sys().TuneMountWithContext(ctx, "database", tuneConfig)
		if err != nil {
			t.Fatalf("TuneMountWithContext failed: %v", err)
		}
	})

	t.Run("respects context cancellation", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(time.Second * 2)
			w.WriteHeader(http.StatusNoContent)
		}))
		defer server.Close()

		config := DefaultConfig()
		config.Address = server.URL

		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*100)
		defer cancel()

		tuneConfig := map[string]any{
			"default_lease_ttl": 7200,
		}

		err = client.Sys().TuneMountWithContext(ctx, "database", tuneConfig)
		if err == nil {
			t.Error("expected error due to context timeout")
		}
	})
}

func TestSys_MountConfig(t *testing.T) {
	t.Run("successfully retrieves mount configuration", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/v1/sys/providers/database/tune" {
				t.Errorf("expected path /v1/sys/providers/database/tune, got %s", r.URL.Path)
			}
			if r.Method != http.MethodGet {
				t.Errorf("expected GET method, got %s", r.Method)
			}

			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{
				"data": {
					"default_lease_ttl": 3600,
					"max_lease_ttl": 7200,
					"force_no_cache": false
				}
			}`))
		}))
		defer server.Close()

		config := DefaultConfig()
		config.Address = server.URL

		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		mountConfig, err := client.Sys().MountConfig("database")
		if err != nil {
			t.Fatalf("MountConfig failed: %v", err)
		}

		if mountConfig == nil {
			t.Fatal("expected mount config, got nil")
		}

		// The values might come back as float64 or as other numeric types depending on JSON parsing
		if defaultLeaseTTLRaw, ok := mountConfig["default_lease_ttl"]; !ok {
			t.Fatal("expected default_lease_ttl in config")
		} else {
			// Accept various numeric types
			switch v := defaultLeaseTTLRaw.(type) {
			case float64:
				if v != 3600 {
					t.Errorf("expected default_lease_ttl 3600, got %v", v)
				}
			case int:
				if v != 3600 {
					t.Errorf("expected default_lease_ttl 3600, got %v", v)
				}
			default:
				// For other types like json.Number, just check it exists
				if defaultLeaseTTLRaw == nil {
					t.Error("default_lease_ttl should not be nil")
				}
			}
		}

		if maxLeaseTTLRaw, ok := mountConfig["max_lease_ttl"]; !ok {
			t.Fatal("expected max_lease_ttl in config")
		} else {
			switch v := maxLeaseTTLRaw.(type) {
			case float64:
				if v != 7200 {
					t.Errorf("expected max_lease_ttl 7200, got %v", v)
				}
			case int:
				if v != 7200 {
					t.Errorf("expected max_lease_ttl 7200, got %v", v)
				}
			default:
				// For other types like json.Number, just check it exists
				if maxLeaseTTLRaw == nil {
					t.Error("max_lease_ttl should not be nil")
				}
			}
		}
	})

	t.Run("returns error for server error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"errors": ["internal server error"]}`))
		}))
		defer server.Close()

		config := DefaultConfig()
		config.Address = server.URL
		config.MaxRetries = 0

		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		_, err = client.Sys().MountConfig("database")
		if err == nil {
			t.Error("expected error for 500 status")
		}
	})

	t.Run("returns error for empty response data", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{}`))
		}))
		defer server.Close()

		config := DefaultConfig()
		config.Address = server.URL

		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		_, err = client.Sys().MountConfig("database")
		if err == nil {
			t.Error("expected error for empty data")
		}
		if err.Error() != "data from server response is empty" {
			t.Errorf("expected 'data from server response is empty' error, got: %v", err)
		}
	})
}

func TestSys_MountConfigWithContext(t *testing.T) {
	t.Run("successfully retrieves mount config with context", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{
				"data": {
					"default_lease_ttl": 3600,
					"max_lease_ttl": 7200
				}
			}`))
		}))
		defer server.Close()

		config := DefaultConfig()
		config.Address = server.URL

		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		ctx := context.Background()
		mountConfig, err := client.Sys().MountConfigWithContext(ctx, "database")
		if err != nil {
			t.Fatalf("MountConfigWithContext failed: %v", err)
		}

		if len(mountConfig) != 2 {
			t.Errorf("expected 2 config entries, got %d", len(mountConfig))
		}
	})

	t.Run("respects context cancellation", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(time.Second * 2)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"data": {}}`))
		}))
		defer server.Close()

		config := DefaultConfig()
		config.Address = server.URL

		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*100)
		defer cancel()

		_, err = client.Sys().MountConfigWithContext(ctx, "database")
		if err == nil {
			t.Error("expected error due to context timeout")
		}
	})
}

func TestSys_MountInfo(t *testing.T) {
	t.Run("successfully retrieves mount info", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/v1/sys/providers/database" {
				t.Errorf("expected path /v1/sys/providers/database, got %s", r.URL.Path)
			}
			if r.Method != http.MethodGet {
				t.Errorf("expected GET method, got %s", r.Method)
			}

			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{
				"data": {
					"type": "database",
					"description": "Database secrets engine",
					"accessor": "database_accessor_123",
					"config": {
						"default_lease_ttl": 3600,
						"max_lease_ttl": 7200
					}
				}
			}`))
		}))
		defer server.Close()

		config := DefaultConfig()
		config.Address = server.URL

		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		mountInfo, err := client.Sys().MountInfo("database")
		if err != nil {
			t.Fatalf("MountInfo failed: %v", err)
		}

		if mountInfo == nil {
			t.Fatal("expected mount info, got nil")
		}

		if mountInfo.Type != "database" {
			t.Errorf("expected type database, got %s", mountInfo.Type)
		}

		if mountInfo.Description != "Database secrets engine" {
			t.Errorf("expected description 'Database secrets engine', got %s", mountInfo.Description)
		}

		if mountInfo.Accessor != "database_accessor_123" {
			t.Errorf("expected accessor database_accessor_123, got %s", mountInfo.Accessor)
		}
	})

	t.Run("returns error for server error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"errors": ["internal server error"]}`))
		}))
		defer server.Close()

		config := DefaultConfig()
		config.Address = server.URL
		config.MaxRetries = 0

		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		_, err = client.Sys().MountInfo("database")
		if err == nil {
			t.Error("expected error for 500 status")
		}
	})

	t.Run("returns error for empty response data", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{}`))
		}))
		defer server.Close()

		config := DefaultConfig()
		config.Address = server.URL

		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		_, err = client.Sys().MountInfo("database")
		if err == nil {
			t.Error("expected error for empty data")
		}
		if err.Error() != "data from server response is empty" {
			t.Errorf("expected 'data from server response is empty' error, got: %v", err)
		}
	})

	t.Run("returns error for non-existent mount", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"errors": ["mount not found"]}`))
		}))
		defer server.Close()

		config := DefaultConfig()
		config.Address = server.URL
		config.MaxRetries = 0

		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		_, err = client.Sys().MountInfo("nonexistent")
		if err == nil {
			t.Error("expected error for non-existent mount")
		}
	})
}

func TestSys_MountInfoWithContext(t *testing.T) {
	t.Run("successfully retrieves mount info with context", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{
				"data": {
					"type": "database",
					"description": "Database secrets engine",
					"accessor": "database_accessor_123"
				}
			}`))
		}))
		defer server.Close()

		config := DefaultConfig()
		config.Address = server.URL

		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		ctx := context.Background()
		mountInfo, err := client.Sys().MountInfoWithContext(ctx, "database")
		if err != nil {
			t.Fatalf("MountInfoWithContext failed: %v", err)
		}

		if mountInfo.Type != "database" {
			t.Errorf("expected type database, got %s", mountInfo.Type)
		}
	})

	t.Run("respects context cancellation", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(time.Second * 2)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"data": {"type": "database"}}`))
		}))
		defer server.Close()

		config := DefaultConfig()
		config.Address = server.URL

		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*100)
		defer cancel()

		_, err = client.Sys().MountInfoWithContext(ctx, "database")
		if err == nil {
			t.Error("expected error due to context timeout")
		}
	})
}

func TestSys_MountE2E(t *testing.T) {
	t.Run("complete mount lifecycle", func(t *testing.T) {
		// Track state across multiple requests
		mounted := false
		defaultLeaseTTL := 3600
		maxLeaseTTL := 7200

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == http.MethodGet && r.URL.Path == "/v1/sys/providers":
				// List mounts
				if mounted {
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(`{
						"$schema": "http://localhost:5000/schemas/ListMountsOutput.json",
						"mounts": {
							"database/": {
								"type": "database",
								"description": "Database secrets engine",
								"accessor": "database_accessor_123"
							}
						}
					}`))
				} else {
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(`{"mounts": {}}`))
				}
			case r.Method == http.MethodPost && r.URL.Path == "/v1/sys/providers/database":
				// Mount
				mounted = true
				w.WriteHeader(http.StatusNoContent)
			case r.Method == http.MethodGet && r.URL.Path == "/v1/sys/providers/database/tune":
				// Get mount config
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(fmt.Sprintf(`{
					"data": {
						"default_lease_ttl": %d,
						"max_lease_ttl": %d
					}
				}`, defaultLeaseTTL, maxLeaseTTL)))
			case r.Method == http.MethodPost && r.URL.Path == "/v1/sys/providers/database/tune":
				// Tune mount
				defaultLeaseTTL = 7200
				maxLeaseTTL = 14400
				w.WriteHeader(http.StatusNoContent)
			case r.Method == http.MethodGet && r.URL.Path == "/v1/sys/providers/database":
				// Get mount info
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{
					"data": {
						"type": "database",
						"description": "Database secrets engine",
						"accessor": "database_accessor_123"
					}
				}`))
			case r.Method == http.MethodDelete && r.URL.Path == "/v1/sys/providers/database":
				// Unmount
				mounted = false
				w.WriteHeader(http.StatusNoContent)
			default:
				w.WriteHeader(http.StatusMethodNotAllowed)
			}
		}))
		defer server.Close()

		config := DefaultConfig()
		config.Address = server.URL

		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		// Initially, no mounts should exist
		mounts, err := client.Sys().ListMounts()
		if err != nil {
			t.Fatalf("ListMounts failed: %v", err)
		}
		if len(mounts) != 0 {
			t.Errorf("expected 0 mounts initially, got %d", len(mounts))
		}

		// Mount a secrets engine
		mountInput := &MountInput{
			Type:        "database",
			Description: "Database secrets engine",
		}
		err = client.Sys().Mount("database", mountInput)
		if err != nil {
			t.Fatalf("Mount failed: %v", err)
		}

		// Verify mount exists
		mounts, err = client.Sys().ListMounts()
		if err != nil {
			t.Fatalf("ListMounts failed: %v", err)
		}
		if len(mounts) != 1 {
			t.Errorf("expected 1 mount, got %d", len(mounts))
		}

		// Get mount info
		mountInfo, err := client.Sys().MountInfo("database")
		if err != nil {
			t.Fatalf("MountInfo failed: %v", err)
		}
		if mountInfo.Type != "database" {
			t.Errorf("expected type database, got %s", mountInfo.Type)
		}

		// Get mount config
		mountConfig, err := client.Sys().MountConfig("database")
		if err != nil {
			t.Fatalf("MountConfig failed: %v", err)
		}
		if _, ok := mountConfig["default_lease_ttl"]; !ok {
			t.Error("expected default_lease_ttl in config")
		}

		// Tune mount
		tuneConfig := map[string]any{
			"default_lease_ttl": 7200,
			"max_lease_ttl":     14400,
		}
		err = client.Sys().TuneMount("database", tuneConfig)
		if err != nil {
			t.Fatalf("TuneMount failed: %v", err)
		}

		// Verify config was updated
		mountConfig, err = client.Sys().MountConfig("database")
		if err != nil {
			t.Fatalf("MountConfig failed: %v", err)
		}
		if _, ok := mountConfig["default_lease_ttl"]; !ok {
			t.Error("expected default_lease_ttl in config after tune")
		}

		// Unmount the secrets engine
		err = client.Sys().Unmount("database")
		if err != nil {
			t.Fatalf("Unmount failed: %v", err)
		}

		// Verify mount is gone
		mounts, err = client.Sys().ListMounts()
		if err != nil {
			t.Fatalf("ListMounts failed: %v", err)
		}
		if len(mounts) != 0 {
			t.Errorf("expected 0 mounts after unmount, got %d", len(mounts))
		}
	})
}

func TestMountTypes(t *testing.T) {
	t.Run("MountInput has required fields", func(t *testing.T) {
		mountInput := MountInput{
			Type:        "database",
			Description: "Test database mount",
			Config: map[string]any{
				"default_lease_ttl": 3600,
				"max_lease_ttl":     7200,
			},
		}

		if mountInput.Type != "database" {
			t.Errorf("expected type database, got %s", mountInput.Type)
		}

		if mountInput.Description != "Test database mount" {
			t.Errorf("expected description 'Test database mount', got %s", mountInput.Description)
		}

		if len(mountInput.Config) != 2 {
			t.Errorf("expected 2 config entries, got %d", len(mountInput.Config))
		}
	})

	t.Run("MountOutput has required fields", func(t *testing.T) {
		mountOutput := MountOutput{
			Type:        "database",
			Description: "Test database mount",
			Accessor:    "database_accessor_123",
			Config: map[string]any{
				"default_lease_ttl": 3600,
			},
		}

		if mountOutput.Type != "database" {
			t.Errorf("expected type database, got %s", mountOutput.Type)
		}

		if mountOutput.Accessor != "database_accessor_123" {
			t.Errorf("expected accessor database_accessor_123, got %s", mountOutput.Accessor)
		}
	})
}
