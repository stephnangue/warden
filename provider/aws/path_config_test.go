package aws

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
	"github.com/stephnangue/warden/provider/sigv4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- test helpers ---

type inmemStorage struct {
	mu   sync.RWMutex
	data map[string]*sdklogical.StorageEntry
}

func newInmemStorage() *inmemStorage {
	return &inmemStorage{data: make(map[string]*sdklogical.StorageEntry)}
}

func (s *inmemStorage) List(_ context.Context, prefix string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var keys []string
	for k := range s.data {
		if len(k) >= len(prefix) && k[:len(prefix)] == prefix {
			keys = append(keys, k[len(prefix):])
		}
	}
	return keys, nil
}

func (s *inmemStorage) Get(_ context.Context, key string) (*sdklogical.StorageEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.data[key], nil
}

func (s *inmemStorage) Put(_ context.Context, entry *sdklogical.StorageEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[entry.Key] = entry
	return nil
}

func (s *inmemStorage) Delete(_ context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, key)
	return nil
}

func (s *inmemStorage) ListPage(_ context.Context, prefix string, _ string, _ int) ([]string, error) {
	return s.List(context.Background(), prefix)
}

func makeFieldData(path *framework.Path, raw map[string]interface{}) *framework.FieldData {
	return &framework.FieldData{
		Raw:    raw,
		Schema: path.Fields,
	}
}

// --- pathConfig tests ---

func TestPathConfig_Schema(t *testing.T) {
	b := &awsBackend{}
	path := b.pathConfig()

	assert.Equal(t, "config", path.Pattern)
	assert.NotNil(t, path.Fields["proxy_domains"])
	assert.NotNil(t, path.Fields["max_body_size"])
	assert.NotNil(t, path.Fields["timeout"])
	assert.NotNil(t, path.Fields["auto_auth_path"])
	assert.NotNil(t, path.Fields["default_role"])

	assert.Equal(t, framework.TypeCommaStringSlice, path.Fields["proxy_domains"].Type)
	assert.Equal(t, framework.TypeInt, path.Fields["max_body_size"].Type)
	assert.Equal(t, framework.TypeDurationSecond, path.Fields["timeout"].Type)
	assert.Equal(t, framework.TypeString, path.Fields["auto_auth_path"].Type)

	assert.NotNil(t, path.Operations[logical.ReadOperation])
	assert.NotNil(t, path.Operations[logical.UpdateOperation])
}

// --- Config Read tests ---

func TestHandleConfigRead(t *testing.T) {
	b := &awsBackend{
		proxyDomains: []string{"example.com"},
		StreamingBackend: &framework.StreamingBackend{
			MaxBodySize:       framework.DefaultMaxBodySize,
			Timeout:           30 * time.Second,
			TransparentConfig: &framework.TransparentConfig{AutoAuthPath: "auth/jwt/", DefaultAuthRole: "reader"},
		},
	}

	resp, err := b.handleConfigRead(context.Background(), nil, nil)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, []string{"example.com"}, resp.Data["proxy_domains"])
	assert.Equal(t, framework.DefaultMaxBodySize, resp.Data["max_body_size"])
	assert.Equal(t, (30 * time.Second).String(), resp.Data["timeout"])
	assert.Equal(t, "auth/jwt/", resp.Data["auto_auth_path"])
	assert.Equal(t, "reader", resp.Data["default_role"])
}

// --- Config Write tests ---

func TestHandleConfigWrite(t *testing.T) {
	b := &awsBackend{
		StreamingBackend: &framework.StreamingBackend{
			TransparentConfig: &framework.TransparentConfig{},
			Logger:            createTestLogger(),
		},
	}
	path := b.pathConfig()

	t.Run("successful update", func(t *testing.T) {
		d := makeFieldData(path, map[string]interface{}{
			"proxy_domains":  "example.com,test.com",
			"timeout":        60,
			"auto_auth_path": "auth/jwt/",
			"default_role":   "admin",
		})
		resp, err := b.handleConfigWrite(context.Background(), nil, d)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "configuration updated", resp.Data["message"])
	})

	t.Run("missing auto_auth_path rejected", func(t *testing.T) {
		b.StreamingBackend.SetTransparentConfig(&framework.TransparentConfig{})
		d := makeFieldData(path, map[string]interface{}{
			"proxy_domains": "example.com",
		})
		resp, err := b.handleConfigWrite(context.Background(), nil, d)
		require.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("persists to storage", func(t *testing.T) {
		storage := newInmemStorage()
		b.StorageView = storage
		b.StreamingBackend.SetTransparentConfig(&framework.TransparentConfig{})
		d := makeFieldData(path, map[string]interface{}{
			"proxy_domains":  "s3.amazonaws.com",
			"auto_auth_path": "auth/cert/",
		})
		resp, err := b.handleConfigWrite(context.Background(), nil, d)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		entry, err := storage.Get(context.Background(), "config")
		require.NoError(t, err)
		require.NotNil(t, entry)
	})
}

// --- ValidateConfig tests ---

func TestValidateConfig(t *testing.T) {
	t.Run("valid config", func(t *testing.T) {
		err := ValidateConfig(map[string]any{
			"proxy_domains": []string{"example.com"},
			"max_body_size": int64(1024),
			"timeout":       "30s",
		})
		assert.NoError(t, err)
	})

	t.Run("unknown key rejected", func(t *testing.T) {
		err := ValidateConfig(map[string]any{
			"unknown_key": "value",
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unknown configuration key")
	})

	t.Run("proxy_domains invalid type", func(t *testing.T) {
		err := ValidateConfig(map[string]any{
			"proxy_domains": "not-an-array",
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "must be an array")
	})

	t.Run("proxy_domains non-string element", func(t *testing.T) {
		err := ValidateConfig(map[string]any{
			"proxy_domains": []any{123},
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "must be a string")
	})

	t.Run("max_body_size negative", func(t *testing.T) {
		err := ValidateConfig(map[string]any{
			"max_body_size": int64(-1),
		})
		assert.Error(t, err)
	})

	t.Run("max_body_size exceeds 100MB", func(t *testing.T) {
		err := ValidateConfig(map[string]any{
			"max_body_size": int64(200_000_000),
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "must not exceed")
	})

	t.Run("max_body_size invalid type", func(t *testing.T) {
		err := ValidateConfig(map[string]any{
			"max_body_size": true,
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "must be an integer")
	})

	t.Run("max_body_size as string", func(t *testing.T) {
		err := ValidateConfig(map[string]any{
			"max_body_size": "1024",
		})
		assert.NoError(t, err)
	})

	t.Run("max_body_size as invalid string", func(t *testing.T) {
		err := ValidateConfig(map[string]any{
			"max_body_size": "not-a-number",
		})
		assert.Error(t, err)
	})

	t.Run("max_body_size as float64", func(t *testing.T) {
		err := ValidateConfig(map[string]any{
			"max_body_size": float64(1024),
		})
		assert.NoError(t, err)
	})

	t.Run("max_body_size as int", func(t *testing.T) {
		err := ValidateConfig(map[string]any{
			"max_body_size": 1024,
		})
		assert.NoError(t, err)
	})

	t.Run("timeout invalid string", func(t *testing.T) {
		err := ValidateConfig(map[string]any{
			"timeout": "invalid",
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid timeout")
	})

	t.Run("timeout negative int", func(t *testing.T) {
		err := ValidateConfig(map[string]any{
			"timeout": -5,
		})
		assert.Error(t, err)
	})

	t.Run("timeout negative float", func(t *testing.T) {
		err := ValidateConfig(map[string]any{
			"timeout": float64(-1),
		})
		assert.Error(t, err)
	})

	t.Run("timeout invalid type", func(t *testing.T) {
		err := ValidateConfig(map[string]any{
			"timeout": true,
		})
		assert.Error(t, err)
	})

	t.Run("empty config valid", func(t *testing.T) {
		err := ValidateConfig(map[string]any{})
		assert.NoError(t, err)
	})
}

// --- SensitiveConfigFields tests ---

func TestSensitiveConfigFields(t *testing.T) {
	b := &awsBackend{}
	fields := b.SensitiveConfigFields()
	assert.Contains(t, fields, "ca_data")
}

// --- Initialize tests ---

func TestInitialize_NoStorage(t *testing.T) {
	b := &awsBackend{
		StreamingBackend: &framework.StreamingBackend{},
	}
	err := b.Initialize(context.Background())
	assert.NoError(t, err)
}

func TestInitialize_EmptyStorage(t *testing.T) {
	storage := newInmemStorage()
	b := &awsBackend{
		StreamingBackend: &framework.StreamingBackend{
			StorageView:       storage,
			TransparentConfig: &framework.TransparentConfig{},
		},
	}
	err := b.Initialize(context.Background())
	assert.NoError(t, err)
}

func TestInitialize_ExistingConfig(t *testing.T) {
	storage := newInmemStorage()
	entry, _ := sdklogical.StorageEntryJSON("config", map[string]any{
		"proxy_domains":  []string{"s3.amazonaws.com"},
		"max_body_size":  int64(5242880),
		"timeout":        "60s",
		"auto_auth_path": "auth/jwt/",
		"default_role":   "reader",
	})
	_ = storage.Put(context.Background(), entry)

	b := &awsBackend{
		StreamingBackend: &framework.StreamingBackend{
			StorageView:       storage,
			TransparentConfig: &framework.TransparentConfig{},
			Logger:            createTestLogger(),
		},
	}

	err := b.Initialize(context.Background())
	require.NoError(t, err)
	assert.Equal(t, []string{"s3.amazonaws.com"}, b.proxyDomains)
	assert.Equal(t, int64(5242880), b.MaxBodySize)
	assert.Equal(t, 60*time.Second, b.Timeout)
}

// --- getCredentials tests ---

func TestGetCredentials(t *testing.T) {
	b := &awsBackend{}

	t.Run("static credentials (no lease)", func(t *testing.T) {
		req := &logical.Request{
			Credential: &credential.Credential{
				Type: credential.TypeAWSAccessKeys,
				Data: map[string]string{
					"access_key_id":     "AKIATEST",
					"secret_access_key": "secret",
					"cred_source":       "warden",
				},
			},
		}
		creds, err := b.getCredentials(req)
		assert.NoError(t, err)
		assert.Equal(t, "AKIATEST", creds.AccessKeyID)
		assert.Equal(t, "secret", creds.SecretAccessKey)
		assert.Equal(t, "warden", creds.Source)
		assert.False(t, creds.CanExpire)
	})

	t.Run("STS credentials (with lease)", func(t *testing.T) {
		req := &logical.Request{
			Credential: &credential.Credential{
				Type:     credential.TypeAWSAccessKeys,
				LeaseTTL: time.Hour,
				Data: map[string]string{
					"access_key_id":     "ASIATEST",
					"secret_access_key": "secret",
					"session_token":     "token",
					"cred_source":       "warden",
				},
			},
		}
		creds, err := b.getCredentials(req)
		assert.NoError(t, err)
		assert.Equal(t, "ASIATEST", creds.AccessKeyID)
		assert.Equal(t, "token", creds.SessionToken)
		assert.True(t, creds.CanExpire)
	})

	t.Run("unsupported type", func(t *testing.T) {
		req := &logical.Request{
			Credential: &credential.Credential{
				Type: credential.TypeVaultToken,
			},
		}
		_, err := b.getCredentials(req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported")
	})
}

// --- extractAccessKeyID tests ---

func TestExtractAccessKeyID(t *testing.T) {
	tests := []struct {
		name     string
		header   string
		expected string
	}{
		{
			name:     "valid header",
			header:   "AWS4-HMAC-SHA256 Credential=AKIATEST/20230101/us-east-1/s3/aws4_request",
			expected: "AKIATEST",
		},
		{
			name:     "no credential",
			header:   "AWS4-HMAC-SHA256 SignedHeaders=host",
			expected: "",
		},
		{
			name:     "credential at end",
			header:   "Credential=",
			expected: "",
		},
		{
			name:     "credential no slash",
			header:   "Credential=AKIATEST",
			expected: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, sigv4.ExtractAccessKeyID(tt.header))
		})
	}
}

// --- getSigner tests ---

func TestGetSigner(t *testing.T) {
	b := &awsBackend{
		signer:   nil,
		s3Signer: nil,
	}
	// Just test the routing logic (nil is fine since we're just checking which pointer)
	// We need real signers to avoid nil panic
	b.signer = newTestSigner()
	b.s3Signer = newTestS3Signer()

	assert.Equal(t, b.s3Signer, b.getSigner("s3"))
	assert.Equal(t, b.s3Signer, b.getSigner("s3-control"))
	assert.Equal(t, b.signer, b.getSigner("dynamodb"))
	assert.Equal(t, b.signer, b.getSigner("sts"))
}

// --- removeAWSChunkedEncoding tests ---

func TestRemoveAWSChunkedEncoding(t *testing.T) {
	t.Run("only aws-chunked", func(t *testing.T) {
		r, _ := http.NewRequest("PUT", "/", nil)
		r.Header.Set("Content-Encoding", "aws-chunked")
		sigv4.RemoveAWSChunkedEncoding(r)
		assert.Empty(t, r.Header.Get("Content-Encoding"))
	})

	t.Run("aws-chunked with gzip", func(t *testing.T) {
		r, _ := http.NewRequest("PUT", "/", nil)
		r.Header.Set("Content-Encoding", "gzip, aws-chunked")
		sigv4.RemoveAWSChunkedEncoding(r)
		assert.Equal(t, "gzip", r.Header.Get("Content-Encoding"))
	})

	t.Run("no content-encoding", func(t *testing.T) {
		r, _ := http.NewRequest("PUT", "/", nil)
		sigv4.RemoveAWSChunkedEncoding(r)
		assert.Empty(t, r.Header.Get("Content-Encoding"))
	})
}

// --- ShutdownHTTPTransport tests ---

func TestShutdownHTTPTransport(t *testing.T) {
	// Should not panic
	ShutdownHTTPTransport()
}

// --- paths tests ---

func TestPaths(t *testing.T) {
	b := &awsBackend{}
	paths := b.paths()
	require.Len(t, paths, 1)
	assert.Equal(t, "config", paths[0].Pattern)
}

// --- helper to create test signers ---

// --- decodeAWSChunkedBody edge cases ---

func TestDecodeAWSChunkedBody_MultipleChunks(t *testing.T) {
	body := []byte("5;chunk-signature=aaa\r\nhello\r\n6;chunk-signature=bbb\r\n world\r\n0;chunk-signature=ccc\r\n\r\n")
	decoded, err := sigv4.DecodeAWSChunkedBody(body)
	require.NoError(t, err)
	assert.Equal(t, "hello world", string(decoded))
}

func TestDecodeAWSChunkedBody_InvalidHexSize(t *testing.T) {
	body := []byte("ZZ;chunk-signature=aaa\r\ndata\r\n")
	_, err := sigv4.DecodeAWSChunkedBody(body)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid chunk size")
}

func TestDecodeAWSChunkedBody_Empty(t *testing.T) {
	body := []byte("0;chunk-signature=aaa\r\n\r\n")
	decoded, err := sigv4.DecodeAWSChunkedBody(body)
	require.NoError(t, err)
	assert.Empty(t, decoded)
}

func TestDecodeAWSChunkedBody_TruncatedData(t *testing.T) {
	body := []byte("a;chunk-signature=aaa\r\nshort\r\n")
	_, err := sigv4.DecodeAWSChunkedBody(body)
	assert.Error(t, err)
}

// --- ValidateConfig json.Number ---

func TestValidateConfig_JsonNumber(t *testing.T) {
	t.Run("valid json.Number max_body_size", func(t *testing.T) {
		err := ValidateConfig(map[string]any{
			"max_body_size": jsonNumber("1024"),
		})
		assert.NoError(t, err)
	})

	t.Run("invalid json.Number max_body_size", func(t *testing.T) {
		err := ValidateConfig(map[string]any{
			"max_body_size": jsonNumber("not-a-number"),
		})
		assert.Error(t, err)
	})
}

func jsonNumber(s string) json.Number {
	return json.Number(s)
}

// --- isAWSChunked ---

func TestIsAWSChunked(t *testing.T) {
	r, _ := http.NewRequest("PUT", "/", nil)
	assert.False(t, sigv4.IsAWSChunked(r))

	r.Header.Set("Content-Encoding", "aws-chunked")
	assert.True(t, sigv4.IsAWSChunked(r))

	r.Header.Set("Content-Encoding", "gzip, aws-chunked")
	assert.True(t, sigv4.IsAWSChunked(r))
}

// --- Factory tests ---

func TestFactory(t *testing.T) {
	storage := newInmemStorage()
	ctx := context.Background()
	conf := &logical.BackendConfig{
		StorageView: storage,
		Logger:      createTestLogger(),
	}
	b, err := Factory(ctx, conf)
	require.NoError(t, err)
	ab := b.(*awsBackend)
	assert.Equal(t, "aws", ab.Type())
	assert.Equal(t, logical.ClassProvider, ab.Class())
	assert.Equal(t, framework.DefaultMaxBodySize, ab.MaxBodySize)
	assert.Equal(t, framework.DefaultTimeout, ab.Timeout)
}

func TestFactory_WithConfig(t *testing.T) {
	storage := newInmemStorage()
	ctx := context.Background()
	conf := &logical.BackendConfig{
		StorageView: storage,
		Logger:      createTestLogger(),
		Config: map[string]any{
			"proxy_domains": []string{"s3.amazonaws.com"},
			"max_body_size": int64(5242880),
			"timeout":       "60s",
		},
	}
	b, err := Factory(ctx, conf)
	require.NoError(t, err)
	ab := b.(*awsBackend)
	assert.Equal(t, int64(5242880), ab.MaxBodySize)
	assert.Equal(t, 60*time.Second, ab.Timeout)
	assert.Equal(t, []string{"s3.amazonaws.com"}, ab.proxyDomains)
}

func TestFactory_InvalidConfig(t *testing.T) {
	storage := newInmemStorage()
	ctx := context.Background()
	conf := &logical.BackendConfig{
		StorageView: storage,
		Logger:      createTestLogger(),
		Config: map[string]any{
			"unknown_field": "value",
		},
	}
	_, err := Factory(ctx, conf)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid configuration")
}

func TestFactory_ShutdownHook(t *testing.T) {
	storage := newInmemStorage()
	ctx := context.Background()
	hookCalled := false
	conf := &logical.BackendConfig{
		StorageView: storage,
		Logger:      createTestLogger(),
		RegisterShutdownHook: func(name string, fn func()) {
			hookCalled = true
			assert.Equal(t, "aws-transport", name)
		},
	}
	_, err := Factory(ctx, conf)
	require.NoError(t, err)
	assert.True(t, hookCalled)
}

// --- handleGatewayStreaming test ---

func TestHandleGatewayStreaming(t *testing.T) {
	// handleGatewayStreaming delegates to handleGateway which needs full setup
	// Just test it doesn't panic with minimal setup (no processor registry = error path)
	b := &awsBackend{
		StreamingBackend: &framework.StreamingBackend{
			Logger:            createTestLogger(),
			TransparentConfig: &framework.TransparentConfig{},
			MaxBodySize:       framework.DefaultMaxBodySize,
			Timeout:           30 * time.Second,
		},
		signer:   v4.NewSigner(),
		s3Signer: v4.NewSigner(),
	}
	b.initializeProcessors()

	// Minimal request - will fail at auth/signature stage but covers entry paths
	httpReq := httptest.NewRequest(http.MethodGet, "/gateway/test", nil)
	rr := httptest.NewRecorder()
	req := &logical.Request{
		Path:           "gateway/test",
		HTTPRequest:    httpReq,
		ResponseWriter: rr,
	}

	// No authorization header = will fail early
	err := b.handleGatewayStreaming(context.Background(), req, nil)
	assert.NoError(t, err) // handleGatewayStreaming always returns nil
	// Should get unauthorized since no auth header
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestProcessRequest_SignatureMismatch(t *testing.T) {
	b := &awsBackend{
		StreamingBackend: &framework.StreamingBackend{
			Logger:            createTestLogger(),
			TransparentConfig: &framework.TransparentConfig{},
			MaxBodySize:       framework.DefaultMaxBodySize,
			Timeout:           30 * time.Second,
		},
		signer:   v4.NewSigner(),
		s3Signer: v4.NewSigner(),
	}
	b.initializeProcessors()

	// Request with valid auth header format but bad signature
	httpReq := httptest.NewRequest(http.MethodGet, "http://s3.us-east-1.amazonaws.com/gateway/test", nil)
	httpReq.Host = "s3.us-east-1.amazonaws.com"
	httpReq.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=my-role/20260401/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=0000000000000000000000000000000000000000000000000000000000000000")
	httpReq.Header.Set("X-Amz-Date", time.Now().UTC().Format("20060102T150405Z"))

	rr := httptest.NewRecorder()
	req := &logical.Request{
		Path:           "gateway/test",
		HTTPRequest:    httpReq,
		ResponseWriter: rr,
	}

	_, _, err := b.processRequest(context.Background(), req)
	assert.Error(t, err) // Signature mismatch
	assert.Equal(t, http.StatusForbidden, rr.Code)
}

func TestProcessRequest_ValidSignature_NoCredential(t *testing.T) {
	b := &awsBackend{
		StreamingBackend: &framework.StreamingBackend{
			Logger:            createTestLogger(),
			TransparentConfig: &framework.TransparentConfig{},
			MaxBodySize:       framework.DefaultMaxBodySize,
			Timeout:           30 * time.Second,
		},
		signer:       v4.NewSigner(),
		s3Signer:     v4.NewSigner(),
		proxyDomains: []string{"amazonaws.com"},
	}
	b.initializeProcessors()

	// Build and properly sign a request using cert-transparent mode
	// (access_key_id = secret_access_key = role name)
	httpReq := httptest.NewRequest(http.MethodGet, "http://s3.us-east-1.amazonaws.com/gateway/my-bucket/key", nil)
	httpReq.Host = "s3.us-east-1.amazonaws.com"
	httpReq.Header.Set("X-Amz-Content-Sha256", sigv4.ComputePayloadHash([]byte{}))

	signingTime := time.Now().UTC()
	creds := aws.Credentials{
		AccessKeyID:     "my-role",
		SecretAccessKey: "my-role",
	}
	signer := v4.NewSigner()
	_ = signer.SignHTTP(context.Background(), creds, httpReq, sigv4.ComputePayloadHash([]byte{}), "s3", "us-east-1", signingTime)

	rr := httptest.NewRecorder()
	req := &logical.Request{
		Path:           "gateway/my-bucket/key",
		HTTPRequest:    httpReq,
		ResponseWriter: rr,
		Credential: &credential.Credential{
			Type: credential.TypeVaultToken, // wrong type
		},
	}

	_, _, err := b.processRequest(context.Background(), req)
	assert.Error(t, err)
	// Should reach getCredentials and fail (unauthorized)
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestProcessRequest_ValidSignature_WithCredential(t *testing.T) {
	// Create a mock upstream
	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer mockUpstream.Close()

	b := &awsBackend{
		StreamingBackend: &framework.StreamingBackend{
			Logger:            createTestLogger(),
			TransparentConfig: &framework.TransparentConfig{},
			MaxBodySize:       framework.DefaultMaxBodySize,
			Timeout:           30 * time.Second,
		},
		signer:       v4.NewSigner(),
		s3Signer:     v4.NewSigner(),
		proxyDomains: []string{"amazonaws.com"},
	}
	b.initializeProcessors()
	b.StreamingBackend.InitProxy(sharedTransport)

	httpReq := httptest.NewRequest(http.MethodGet, "http://s3.us-east-1.amazonaws.com/gateway/my-bucket/key", nil)
	httpReq.Host = "s3.us-east-1.amazonaws.com"
	httpReq.Header.Set("X-Amz-Content-Sha256", sigv4.ComputePayloadHash([]byte{}))

	signingTime := time.Now().UTC()
	creds := aws.Credentials{
		AccessKeyID:     "my-role",
		SecretAccessKey: "my-role",
	}
	signer := v4.NewSigner()
	_ = signer.SignHTTP(context.Background(), creds, httpReq, sigv4.ComputePayloadHash([]byte{}), "s3", "us-east-1", signingTime)

	rr := httptest.NewRecorder()
	req := &logical.Request{
		Path:           "gateway/my-bucket/key",
		HTTPRequest:    httpReq,
		ResponseWriter: rr,
		Credential: &credential.Credential{
			Type: credential.TypeAWSAccessKeys,
			Data: map[string]string{
				"access_key_id":     "AKIAREALKEY",
				"secret_access_key": "realsecret",
				"cred_source":       "warden",
			},
		},
	}

	r, body, err := b.processRequest(context.Background(), req)
	// Should succeed through processRequest (resign will work)
	require.NoError(t, err)
	assert.NotNil(t, r)
	assert.NotNil(t, body)

	// Verify the request was re-signed with real credentials
	assert.Contains(t, r.Header.Get("Authorization"), "AKIAREALKEY")
}

func TestForwardDirect(t *testing.T) {
	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Custom", "test")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("response body"))
	}))
	defer mockUpstream.Close()

	b := &awsBackend{
		StreamingBackend: &framework.StreamingBackend{
			Logger: createTestLogger(),
		},
	}
	b.StreamingBackend.InitProxy(sharedTransport)

	r := httptest.NewRequest(http.MethodGet, mockUpstream.URL+"/test", nil)
	r.RequestURI = ""
	rr := httptest.NewRecorder()

	sigv4.ForwardDirect(b.Logger, rr, r, []byte{}, b.Proxy.Transport)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "test", rr.Header().Get("X-Custom"))
	assert.Contains(t, rr.Body.String(), "response body")
}

func TestProcessRequest_ExpiredSignature(t *testing.T) {
	b := &awsBackend{
		StreamingBackend: &framework.StreamingBackend{
			Logger:            createTestLogger(),
			TransparentConfig: &framework.TransparentConfig{},
			MaxBodySize:       framework.DefaultMaxBodySize,
		},
		signer:   v4.NewSigner(),
		s3Signer: v4.NewSigner(),
	}
	b.initializeProcessors()

	httpReq := httptest.NewRequest(http.MethodGet, "http://s3.us-east-1.amazonaws.com/gateway/test", nil)
	httpReq.Host = "s3.us-east-1.amazonaws.com"
	httpReq.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=my-role/20200101/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890")
	httpReq.Header.Set("X-Amz-Date", "20200101T000000Z") // Very old date

	rr := httptest.NewRecorder()
	req := &logical.Request{
		Path:           "gateway/test",
		HTTPRequest:    httpReq,
		ResponseWriter: rr,
	}

	_, _, err := b.processRequest(context.Background(), req)
	assert.Error(t, err) // Expired signature
	assert.Equal(t, http.StatusForbidden, rr.Code)
}

func newTestSigner() *v4.Signer {
	return v4.NewSigner()
}

func newTestS3Signer() *v4.Signer {
	return v4.NewSigner(func(o *v4.SignerOptions) {
		o.DisableURIPathEscaping = true
	})
}
