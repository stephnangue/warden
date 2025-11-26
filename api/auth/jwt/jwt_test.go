package jwt

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stephnangue/warden/api"
)

func TestNew(t *testing.T) {
	t.Run("success with token", func(t *testing.T) {
		auth, err := New("test-role", WithToken("test-token"))
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if auth == nil {
			t.Fatal("expected JWTAuth instance, got nil")
		}
		if auth.roleName != "test-role" {
			t.Errorf("expected roleName to be 'test-role', got '%s'", auth.roleName)
		}
		if auth.token != "test-token" {
			t.Errorf("expected token to be 'test-token', got '%s'", auth.token)
		}
		if auth.mountPath != DefaultMountPath {
			t.Errorf("expected mountPath to be '%s', got '%s'", DefaultMountPath, auth.mountPath)
		}
	})

	t.Run("error when no role name", func(t *testing.T) {
		auth, err := New("", WithToken("test-token"))
		if err != ErrNoRoleName {
			t.Errorf("expected ErrNoRoleName, got %v", err)
		}
		if auth != nil {
			t.Errorf("expected nil JWTAuth, got %v", auth)
		}
	})

	t.Run("error when no token specified", func(t *testing.T) {
		auth, err := New("test-role")
		if err != ErrNoToken {
			t.Errorf("expected ErrNoToken, got %v", err)
		}
		if auth != nil {
			t.Errorf("expected nil JWTAuth, got %v", auth)
		}
	})

	t.Run("error when mount path is empty", func(t *testing.T) {
		auth, err := New("test-role", WithToken("test-token"), func(a *JWTAuth) error {
			a.mountPath = ""
			return nil
		})
		if err != ErrInvalidMountPath {
			t.Errorf("expected ErrInvalidMountPath, got %v", err)
		}
		if auth != nil {
			t.Errorf("expected nil JWTAuth, got %v", auth)
		}
	})

	t.Run("multiple options", func(t *testing.T) {
		auth, err := New("test-role",
			WithToken("test-token"),
			func(a *JWTAuth) error {
				a.mountPath = "custom-jwt"
				return nil
			},
		)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if auth.mountPath != "custom-jwt" {
			t.Errorf("expected mountPath to be 'custom-jwt', got '%s'", auth.mountPath)
		}
	})
}

func TestWithToken(t *testing.T) {
	t.Run("sets token correctly", func(t *testing.T) {
		auth := &JWTAuth{}
		opt := WithToken("my-token")
		err := opt(auth)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if auth.token != "my-token" {
			t.Errorf("expected token to be 'my-token', got '%s'", auth.token)
		}
	})
}

func TestLogin(t *testing.T) {
	t.Run("success with direct token", func(t *testing.T) {
		// Create a test server that simulates the Warden API
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/v1/auth/jwt/login" {
				t.Errorf("expected path '/v1/auth/jwt/login', got '%s'", r.URL.Path)
			}
			if r.Method != http.MethodPut {
				t.Errorf("expected method PUT, got %s", r.Method)
			}
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"auth": {"client_token": "test-client-token"}}`))
		}))
		defer server.Close()

		client, err := api.NewClient(&api.Config{
			Address: server.URL,
		})
		if err != nil {
			t.Fatalf("failed to create client: %v", err)
		}

		auth, err := New("test-role", WithToken("test-token"))
		if err != nil {
			t.Fatalf("failed to create JWTAuth: %v", err)
		}

		resource, err := auth.Login(context.Background(), client)
		if err != nil {
			t.Fatalf("Login failed: %v", err)
		}
		if resource == nil {
			t.Fatal("expected resource, got nil")
		}
	})

	t.Run("success with token containing whitespace", func(t *testing.T) {
		var receivedToken string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Parse the request body to check the token
			var reqData map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&reqData); err != nil {
				t.Fatalf("failed to parse request body: %v", err)
			}
			receivedToken = reqData["jwt"].(string)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"auth": {"client_token": "test-client-token"}}`))
		}))
		defer server.Close()

		client, err := api.NewClient(&api.Config{
			Address: server.URL,
		})
		if err != nil {
			t.Fatalf("failed to create client: %v", err)
		}

		auth, err := New("test-role", WithToken("  test-token  \n"))
		if err != nil {
			t.Fatalf("failed to create JWTAuth: %v", err)
		}

		_, err = auth.Login(context.Background(), client)
		if err != nil {
			t.Fatalf("Login failed: %v", err)
		}
		if receivedToken != "test-token" {
			t.Errorf("expected token to be trimmed to 'test-token', got '%s'", receivedToken)
		}
	})

	t.Run("success with token from file", func(t *testing.T) {
		// Create a temporary token file
		tmpDir := t.TempDir()
		tokenFile := filepath.Join(tmpDir, "token")
		tokenContent := "file-token"
		if err := os.WriteFile(tokenFile, []byte(tokenContent), 0600); err != nil {
			t.Fatalf("failed to write token file: %v", err)
		}

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"auth": {"client_token": "test-client-token"}}`))
		}))
		defer server.Close()

		client, err := api.NewClient(&api.Config{
			Address: server.URL,
		})
		if err != nil {
			t.Fatalf("failed to create client: %v", err)
		}

		auth, err := New("test-role", func(a *JWTAuth) error {
			a.tokenPath = tokenFile
			return nil
		})
		if err != nil {
			t.Fatalf("failed to create JWTAuth: %v", err)
		}

		resource, err := auth.Login(context.Background(), client)
		if err != nil {
			t.Fatalf("Login failed: %v", err)
		}
		if resource == nil {
			t.Fatal("expected resource, got nil")
		}
	})

	t.Run("error when token file not found", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"auth": {"client_token": "test-client-token"}}`))
		}))
		defer server.Close()

		client, err := api.NewClient(&api.Config{
			Address: server.URL,
		})
		if err != nil {
			t.Fatalf("failed to create client: %v", err)
		}

		auth, err := New("test-role", func(a *JWTAuth) error {
			a.tokenPath = "/nonexistent/path/token"
			return nil
		})
		if err != nil {
			t.Fatalf("failed to create JWTAuth: %v", err)
		}

		_, err = auth.Login(context.Background(), client)
		if err == nil {
			t.Fatal("expected error when token file doesn't exist, got nil")
		}
	})

	t.Run("error when token file is empty", func(t *testing.T) {
		// Create an empty token file
		tmpDir := t.TempDir()
		tokenFile := filepath.Join(tmpDir, "empty-token")
		if err := os.WriteFile(tokenFile, []byte(""), 0600); err != nil {
			t.Fatalf("failed to write token file: %v", err)
		}

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"auth": {"client_token": "test-client-token"}}`))
		}))
		defer server.Close()

		client, err := api.NewClient(&api.Config{
			Address: server.URL,
		})
		if err != nil {
			t.Fatalf("failed to create client: %v", err)
		}

		auth, err := New("test-role", func(a *JWTAuth) error {
			a.tokenPath = tokenFile
			return nil
		})
		if err != nil {
			t.Fatalf("failed to create JWTAuth: %v", err)
		}

		_, err = auth.Login(context.Background(), client)
		if err == nil {
			t.Fatal("expected error when token file is empty, got nil")
		}
		if err != nil && err.Error() != "no token specified: got empty token from "+tokenFile {
			t.Errorf("expected specific error message, got: %v", err)
		}
	})

	t.Run("custom mount path", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/v1/auth/custom-jwt/login" {
				t.Errorf("expected path '/v1/auth/custom-jwt/login', got '%s'", r.URL.Path)
			}
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"auth": {"client_token": "test-client-token"}}`))
		}))
		defer server.Close()

		client, err := api.NewClient(&api.Config{
			Address: server.URL,
		})
		if err != nil {
			t.Fatalf("failed to create client: %v", err)
		}

		auth, err := New("test-role",
			WithToken("test-token"),
			func(a *JWTAuth) error {
				a.mountPath = "custom-jwt"
				return nil
			},
		)
		if err != nil {
			t.Fatalf("failed to create JWTAuth: %v", err)
		}

		_, err = auth.Login(context.Background(), client)
		if err != nil {
			t.Fatalf("Login failed: %v", err)
		}
	})
}

func TestJWTAuthImplementsAuthMethod(t *testing.T) {
	// This test ensures that JWTAuth implements the api.AuthMethod interface
	var _ api.AuthMethod = &JWTAuth{}
}
