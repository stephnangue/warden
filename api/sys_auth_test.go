package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSys_ListAuth(t *testing.T) {
	t.Run("successfully lists auth backends", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/v1/sys/auth" {
				t.Errorf("expected path /v1/sys/auth, got %s", r.URL.Path)
			}
			if r.Method != http.MethodGet {
				t.Errorf("expected GET method, got %s", r.Method)
			}

			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{
				"data": {
					"mounts": {
						"token/": {
							"type": "token",
							"description": "Token authentication",
							"accessor": "token_accessor_123",
							"config": {
								"default_lease_ttl": 0,
								"max_lease_ttl": 0
							}
						},
						"userpass/": {
							"type": "userpass",
							"description": "Username and password authentication",
							"accessor": "userpass_accessor_456",
							"config": {
								"default_lease_ttl": 3600,
								"max_lease_ttl": 7200
							}
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

		auths, err := client.Sys().ListAuth()
		if err != nil {
			t.Fatalf("ListAuth failed: %v", err)
		}

		if auths == nil {
			t.Fatal("expected auths map, got nil")
		}

		if len(auths) != 2 {
			t.Errorf("expected 2 auth backends, got %d", len(auths))
		}

		tokenAuth, ok := auths["token/"]
		if !ok {
			t.Fatal("expected token/ auth backend")
		}

		if tokenAuth.Type != "token" {
			t.Errorf("expected type token, got %s", tokenAuth.Type)
		}

		if tokenAuth.Description != "Token authentication" {
			t.Errorf("expected description 'Token authentication', got %s", tokenAuth.Description)
		}

		if tokenAuth.Accessor != "token_accessor_123" {
			t.Errorf("expected accessor token_accessor_123, got %s", tokenAuth.Accessor)
		}

		userpassAuth, ok := auths["userpass/"]
		if !ok {
			t.Fatal("expected userpass/ auth backend")
		}

		if userpassAuth.Type != "userpass" {
			t.Errorf("expected type userpass, got %s", userpassAuth.Type)
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

		_, err = client.Sys().ListAuth()
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

		_, err = client.Sys().ListAuth()
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

		_, err = client.Sys().ListAuth()
		if err == nil {
			t.Error("expected error for invalid JSON")
		}
	})

	t.Run("handles empty auth backends list", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"data": {"mounts": {}}}`))
		}))
		defer server.Close()

		config := DefaultConfig()
		config.Address = server.URL

		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		auths, err := client.Sys().ListAuth()
		if err != nil {
			t.Fatalf("ListAuth failed: %v", err)
		}

		if len(auths) != 0 {
			t.Errorf("expected empty auth backends map, got %d entries", len(auths))
		}
	})
}

func TestSys_ListAuthWithContext(t *testing.T) {
	t.Run("successfully lists auth backends with context", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{
				"data": {
					"mounts": {
						"token/": {
							"type": "token",
							"description": "Token authentication",
							"accessor": "token_accessor_123"
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

		ctx := context.Background()
		auths, err := client.Sys().ListAuthWithContext(ctx)
		if err != nil {
			t.Fatalf("ListAuthWithContext failed: %v", err)
		}

		if len(auths) != 1 {
			t.Errorf("expected 1 auth backend, got %d", len(auths))
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

		_, err = client.Sys().ListAuthWithContext(ctx)
		if err == nil {
			t.Error("expected error due to context timeout")
		}
	})

	t.Run("respects context deadline", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(time.Millisecond * 500)
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

		ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(time.Millisecond*50))
		defer cancel()

		_, err = client.Sys().ListAuthWithContext(ctx)
		if err == nil {
			t.Error("expected error due to context deadline")
		}
	})
}

func TestSys_EnableAuth(t *testing.T) {
	t.Run("successfully enables auth backend", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/v1/sys/auth/userpass" {
				t.Errorf("expected path /v1/sys/auth/userpass, got %s", r.URL.Path)
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

		authInput := &AuthMounthInput{
			Type:        "userpass",
			Description: "Test userpass auth backend",
			Config: map[string]any{
				"default_lease_ttl": 3600,
				"max_lease_ttl":     7200,
			},
		}

		err = client.Sys().EnableAuth("userpass", authInput)
		if err != nil {
			t.Fatalf("EnableAuth failed: %v", err)
		}
	})

	t.Run("returns error for server error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"errors": ["invalid auth type"]}`))
		}))
		defer server.Close()

		config := DefaultConfig()
		config.Address = server.URL
		config.MaxRetries = 0

		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		authInput := &AuthMounthInput{
			Type: "invalid",
		}

		err = client.Sys().EnableAuth("test", authInput)
		if err == nil {
			t.Error("expected error for invalid auth type")
		}
	})

	t.Run("handles path with special characters", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/v1/sys/auth/my-auth-backend" {
				t.Errorf("expected path /v1/sys/auth/my-auth-backend, got %s", r.URL.Path)
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

		authInput := &AuthMounthInput{
			Type: "userpass",
		}

		err = client.Sys().EnableAuth("my-auth-backend", authInput)
		if err != nil {
			t.Fatalf("EnableAuth failed: %v", err)
		}
	})

	t.Run("handles auth backend with complex config", func(t *testing.T) {
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

		authInput := &AuthMounthInput{
			Type:        "ldap",
			Description: "LDAP auth backend",
			Config: map[string]any{
				"url":              "ldap://ldap.example.com",
				"userdn":           "ou=Users,dc=example,dc=com",
				"groupdn":          "ou=Groups,dc=example,dc=com",
				"default_lease_ttl": 3600,
				"max_lease_ttl":     7200,
			},
		}

		err = client.Sys().EnableAuth("ldap", authInput)
		if err != nil {
			t.Fatalf("EnableAuth failed: %v", err)
		}
	})
}

func TestSys_EnableAuthWithContext(t *testing.T) {
	t.Run("successfully enables auth backend with context", func(t *testing.T) {
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
		authInput := &AuthMounthInput{
			Type: "userpass",
		}

		err = client.Sys().EnableAuthWithContext(ctx, "userpass", authInput)
		if err != nil {
			t.Fatalf("EnableAuthWithContext failed: %v", err)
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

		authInput := &AuthMounthInput{
			Type: "userpass",
		}

		err = client.Sys().EnableAuthWithContext(ctx, "userpass", authInput)
		if err == nil {
			t.Error("expected error due to context timeout")
		}
	})

	t.Run("handles nil auth input", func(t *testing.T) {
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
		err = client.Sys().EnableAuthWithContext(ctx, "userpass", nil)
		if err != nil {
			t.Fatalf("EnableAuthWithContext with nil input failed: %v", err)
		}
	})
}

func TestSys_DisableAuth(t *testing.T) {
	t.Run("successfully disables auth backend", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/v1/sys/auth/userpass" {
				t.Errorf("expected path /v1/sys/auth/userpass, got %s", r.URL.Path)
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

		err = client.Sys().DisableAuth("userpass")
		if err != nil {
			t.Fatalf("DisableAuth failed: %v", err)
		}
	})

	t.Run("returns error for non-existent auth backend", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"errors": ["auth backend not found"]}`))
		}))
		defer server.Close()

		config := DefaultConfig()
		config.Address = server.URL
		config.MaxRetries = 0

		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		err = client.Sys().DisableAuth("nonexistent")
		if err == nil {
			t.Error("expected error for non-existent auth backend")
		}
	})

	t.Run("handles path with special characters", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/v1/sys/auth/my-auth-backend" {
				t.Errorf("expected path /v1/sys/auth/my-auth-backend, got %s", r.URL.Path)
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

		err = client.Sys().DisableAuth("my-auth-backend")
		if err != nil {
			t.Fatalf("DisableAuth failed: %v", err)
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

		err = client.Sys().DisableAuth("userpass")
		if err == nil {
			t.Error("expected error for 500 status")
		}
	})
}

func TestSys_DisableAuthWithContext(t *testing.T) {
	t.Run("successfully disables auth backend with context", func(t *testing.T) {
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
		err = client.Sys().DisableAuthWithContext(ctx, "userpass")
		if err != nil {
			t.Fatalf("DisableAuthWithContext failed: %v", err)
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

		err = client.Sys().DisableAuthWithContext(ctx, "userpass")
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

		err = client.Sys().DisableAuthWithContext(ctx, "userpass")
		if err == nil {
			t.Error("expected error due to context deadline")
		}
	})
}

func TestSys_AuthE2E(t *testing.T) {
	t.Run("complete auth lifecycle", func(t *testing.T) {
		// Track state across multiple requests
		authEnabled := false

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodGet:
				// List auth backends
				if authEnabled {
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(`{
						"data": {
							"mounts": {
								"userpass/": {
									"type": "userpass",
									"description": "Username and password authentication",
									"accessor": "userpass_accessor_123"
								}
							}
						}
					}`))
				} else {
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(`{"data": {"mounts": {}}}`))
				}
			case http.MethodPost:
				// Enable auth
				authEnabled = true
				w.WriteHeader(http.StatusNoContent)
			case http.MethodDelete:
				// Disable auth
				authEnabled = false
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

		// Initially, no auth backends should be enabled (except token which is default)
		auths, err := client.Sys().ListAuth()
		if err != nil {
			t.Fatalf("ListAuth failed: %v", err)
		}
		if len(auths) != 0 {
			t.Errorf("expected 0 auth backends initially, got %d", len(auths))
		}

		// Enable an auth backend
		authInput := &AuthMounthInput{
			Type:        "userpass",
			Description: "Username and password authentication",
		}
		err = client.Sys().EnableAuth("userpass/", authInput)
		if err != nil {
			t.Fatalf("EnableAuth failed: %v", err)
		}

		// Verify auth is enabled
		auths, err = client.Sys().ListAuth()
		if err != nil {
			t.Fatalf("ListAuth failed: %v", err)
		}
		if len(auths) != 1 {
			t.Errorf("expected 1 auth backend, got %d", len(auths))
		}

		// Disable the auth backend
		err = client.Sys().DisableAuth("userpass/")
		if err != nil {
			t.Fatalf("DisableAuth failed: %v", err)
		}

		// Verify auth is disabled
		auths, err = client.Sys().ListAuth()
		if err != nil {
			t.Fatalf("ListAuth failed: %v", err)
		}
		if len(auths) != 0 {
			t.Errorf("expected 0 auth backends after disable, got %d", len(auths))
		}
	})
}

func TestSys_AuthInfo(t *testing.T) {
	t.Run("successfully retrieves auth info", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/v1/sys/auth/userpass" {
				t.Errorf("expected path /v1/sys/auth/userpass, got %s", r.URL.Path)
			}
			if r.Method != http.MethodGet {
				t.Errorf("expected GET method, got %s", r.Method)
			}

			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{
				"data": {
					"type": "userpass",
					"description": "Username and password authentication",
					"accessor": "userpass_accessor_123",
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

		authInfo, err := client.Sys().AuthInfo("userpass")
		if err != nil {
			t.Fatalf("AuthInfo failed: %v", err)
		}

		if authInfo == nil {
			t.Fatal("expected auth info, got nil")
		}

		if authInfo.Type != "userpass" {
			t.Errorf("expected type userpass, got %s", authInfo.Type)
		}

		if authInfo.Description != "Username and password authentication" {
			t.Errorf("expected description 'Username and password authentication', got %s", authInfo.Description)
		}

		if authInfo.Accessor != "userpass_accessor_123" {
			t.Errorf("expected accessor userpass_accessor_123, got %s", authInfo.Accessor)
		}

		if authInfo.Config == nil {
			t.Fatal("expected config, got nil")
		}

		// Config values can be various types, just verify it exists
		if _, ok := authInfo.Config["default_lease_ttl"]; !ok {
			t.Error("expected default_lease_ttl in config")
		}
		if _, ok := authInfo.Config["max_lease_ttl"]; !ok {
			t.Error("expected max_lease_ttl in config")
		}
	})

	t.Run("returns error for non-existent auth", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"errors": ["auth method not found"]}`))
		}))
		defer server.Close()

		config := DefaultConfig()
		config.Address = server.URL
		config.MaxRetries = 0

		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		_, err = client.Sys().AuthInfo("nonexistent")
		if err == nil {
			t.Error("expected error for non-existent auth")
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

		_, err = client.Sys().AuthInfo("userpass")
		if err == nil {
			t.Error("expected error for empty data")
		}
		if err.Error() != "data from server response is empty" {
			t.Errorf("expected 'data from server response is empty' error, got: %v", err)
		}
	})

	t.Run("handles path with special characters", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/v1/sys/auth/my-auth-backend" {
				t.Errorf("expected path /v1/sys/auth/my-auth-backend, got %s", r.URL.Path)
			}
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{
				"data": {
					"type": "jwt",
					"description": "JWT auth",
					"accessor": "jwt_accessor_456"
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

		authInfo, err := client.Sys().AuthInfo("my-auth-backend")
		if err != nil {
			t.Fatalf("AuthInfo failed: %v", err)
		}

		if authInfo.Type != "jwt" {
			t.Errorf("expected type jwt, got %s", authInfo.Type)
		}
	})
}

func TestSys_AuthInfoWithContext(t *testing.T) {
	t.Run("successfully retrieves auth info with context", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{
				"data": {
					"type": "userpass",
					"description": "Test auth",
					"accessor": "accessor_123"
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
		authInfo, err := client.Sys().AuthInfoWithContext(ctx, "userpass")
		if err != nil {
			t.Fatalf("AuthInfoWithContext failed: %v", err)
		}

		if authInfo.Type != "userpass" {
			t.Errorf("expected type userpass, got %s", authInfo.Type)
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

		_, err = client.Sys().AuthInfoWithContext(ctx, "userpass")
		if err == nil {
			t.Error("expected error due to context timeout")
		}
	})
}

func TestSys_TuneAuth(t *testing.T) {
	t.Run("successfully tunes auth backend", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/v1/sys/auth/userpass/tune" {
				t.Errorf("expected path /v1/sys/auth/userpass/tune, got %s", r.URL.Path)
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

		err = client.Sys().TuneAuth("userpass", tuneConfig)
		if err != nil {
			t.Fatalf("TuneAuth failed: %v", err)
		}
	})

	t.Run("returns error for non-existent auth", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"errors": ["auth method not found"]}`))
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
			"default_lease_ttl": 3600,
		}

		err = client.Sys().TuneAuth("nonexistent", tuneConfig)
		if err == nil {
			t.Error("expected error for non-existent auth")
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

		err = client.Sys().TuneAuth("userpass", map[string]any{})
		if err != nil {
			t.Fatalf("TuneAuth with empty config failed: %v", err)
		}
	})

	t.Run("handles nil config", func(t *testing.T) {
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

		err = client.Sys().TuneAuth("userpass", nil)
		if err != nil {
			t.Fatalf("TuneAuth with nil config failed: %v", err)
		}
	})

	t.Run("handles complex config", func(t *testing.T) {
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

		tuneConfig := map[string]any{
			"default_lease_ttl": 3600,
			"max_lease_ttl":     7200,
			"token_policies":    []string{"default", "admin"},
			"jwks": map[string]any{
				"url":       "https://example.com/.well-known/jwks.json",
				"cache_ttl": 86400,
			},
		}

		err = client.Sys().TuneAuth("jwt", tuneConfig)
		if err != nil {
			t.Fatalf("TuneAuth with complex config failed: %v", err)
		}
	})

	t.Run("handles path with special characters", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/v1/sys/auth/my-auth-backend/tune" {
				t.Errorf("expected path /v1/sys/auth/my-auth-backend/tune, got %s", r.URL.Path)
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
			"default_lease_ttl": 3600,
		}

		err = client.Sys().TuneAuth("my-auth-backend", tuneConfig)
		if err != nil {
			t.Fatalf("TuneAuth failed: %v", err)
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

		tuneConfig := map[string]any{
			"default_lease_ttl": 3600,
		}

		err = client.Sys().TuneAuth("userpass", tuneConfig)
		if err == nil {
			t.Error("expected error for 500 status")
		}
	})
}

func TestSys_TuneAuthWithContext(t *testing.T) {
	t.Run("successfully tunes auth with context", func(t *testing.T) {
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
			"default_lease_ttl": 3600,
		}

		err = client.Sys().TuneAuthWithContext(ctx, "userpass", tuneConfig)
		if err != nil {
			t.Fatalf("TuneAuthWithContext failed: %v", err)
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
			"default_lease_ttl": 3600,
		}

		err = client.Sys().TuneAuthWithContext(ctx, "userpass", tuneConfig)
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

		tuneConfig := map[string]any{
			"default_lease_ttl": 3600,
		}

		err = client.Sys().TuneAuthWithContext(ctx, "userpass", tuneConfig)
		if err == nil {
			t.Error("expected error due to context deadline")
		}
	})
}

func TestAuthTypeAliases(t *testing.T) {
	t.Run("AuthMounthInput is alias of MountInput", func(t *testing.T) {
		var authInput AuthMounthInput
		var mountInput MountInput

		// Should have the same fields
		authInput = AuthMounthInput{
			Type:        "userpass",
			Description: "Test",
			Config:      map[string]any{"key": "value"},
		}

		mountInput = MountInput{
			Type:        "userpass",
			Description: "Test",
			Config:      map[string]any{"key": "value"},
		}

		// Since they're aliases, they should be assignable
		authInput = AuthMounthInput(mountInput)
		if authInput.Type != "userpass" {
			t.Error("type alias assignment failed")
		}
	})

	t.Run("AuthMountOutput is alias of MountOutput", func(t *testing.T) {
		var authOutput AuthMountOutput
		var mountOutput MountOutput

		authOutput = AuthMountOutput{
			Type:        "userpass",
			Description: "Test",
			Accessor:    "accessor_123",
			Config:      map[string]any{"key": "value"},
		}

		mountOutput = MountOutput{
			Type:        "userpass",
			Description: "Test",
			Accessor:    "accessor_123",
			Config:      map[string]any{"key": "value"},
		}

		// Since they're aliases, they should be assignable
		authOutput = AuthMountOutput(mountOutput)
		if authOutput.Type != "userpass" {
			t.Error("type alias assignment failed")
		}
	})
}
