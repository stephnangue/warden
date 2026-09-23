package sigv4

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/stephnangue/warden/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createTestLogger() *logger.GatedLogger {
	config := &logger.Config{
		Level:   logger.TraceLevel,
		Format:  logger.DefaultFormat,
		Outputs: []io.Writer{io.Discard},
	}
	gl, _ := logger.NewGatedLogger(config, logger.GatedWriterConfig{
		Underlying:   io.Discard,
		InitialState: logger.GateOpen,
	})
	return gl
}

// --- IsSigV4Request ---

func TestIsSigV4Request(t *testing.T) {
	tests := []struct {
		name     string
		authHdr  string
		expected bool
	}{
		{"valid SigV4", "AWS4-HMAC-SHA256 Credential=AKIA.../s3/aws4_request", true},
		{"bearer token", "Bearer some-token", false},
		{"empty header", "", false},
		{"partial match", "AWS4-HMAC", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, _ := http.NewRequest("GET", "/", nil)
			if tt.authHdr != "" {
				r.Header.Set("Authorization", tt.authHdr)
			}
			assert.Equal(t, tt.expected, IsSigV4Request(r))
		})
	}
}

// --- ExtractFromAuthHeader ---

func TestExtractFromAuthHeader(t *testing.T) {
	tests := []struct {
		name     string
		header   string
		wantSvc  string
		wantReg  string
		wantAKID string
		wantErr  bool
	}{
		{
			name:     "valid header",
			header:   "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20231215/us-east-1/s3/aws4_request",
			wantSvc:  "s3",
			wantReg:  "us-east-1",
			wantAKID: "AKIAIOSFODNN7EXAMPLE",
		},
		{
			name:     "scaleway region",
			header:   "AWS4-HMAC-SHA256 Credential=SCWXXXXXXXXXXXXXXXXX/20260410/fr-par/s3/aws4_request",
			wantSvc:  "s3",
			wantReg:  "fr-par",
			wantAKID: "SCWXXXXXXXXXXXXXXXXX",
		},
		{
			name:     "JWT as access key",
			header:   "AWS4-HMAC-SHA256 Credential=eyJhbGciOiJSUzI1NiJ9/20260410/nl-ams/s3/aws4_request",
			wantSvc:  "s3",
			wantReg:  "nl-ams",
			wantAKID: "eyJhbGciOiJSUzI1NiJ9",
		},
		{
			name:    "empty header",
			header:  "",
			wantErr: true,
		},
		{
			name:    "invalid format",
			header:  "Bearer some-token",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, reg, akid, err := ExtractFromAuthHeader(tt.header)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.wantSvc, svc)
				assert.Equal(t, tt.wantReg, reg)
				assert.Equal(t, tt.wantAKID, akid)
			}
		})
	}
}

// --- ExtractAccessKeyID ---

func TestExtractAccessKeyID(t *testing.T) {
	tests := []struct {
		name     string
		header   string
		expected string
	}{
		{
			name:     "standard AWS key",
			header:   "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20231215/us-east-1/s3/aws4_request",
			expected: "AKIAIOSFODNN7EXAMPLE",
		},
		{
			name:     "scaleway key",
			header:   "AWS4-HMAC-SHA256 Credential=SCWXXXXXXXXXXXXXXXXX/20260410/fr-par/s3/aws4_request",
			expected: "SCWXXXXXXXXXXXXXXXXX",
		},
		{
			name:     "JWT key",
			header:   "AWS4-HMAC-SHA256 Credential=eyJhbGciOiJSUzI1NiJ9/20260410/fr-par/s3/aws4_request",
			expected: "eyJhbGciOiJSUzI1NiJ9",
		},
		{
			name:     "no credential",
			header:   "AWS4-HMAC-SHA256 SignedHeaders=host",
			expected: "",
		},
		{
			name:     "credential no slash",
			header:   "Credential=AKIATEST",
			expected: "",
		},
		{
			name:     "empty",
			header:   "",
			expected: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, ExtractAccessKeyID(tt.header))
		})
	}
}

// --- ComputePayloadHash ---

func TestComputePayloadHash(t *testing.T) {
	t.Run("empty body", func(t *testing.T) {
		hash := ComputePayloadHash([]byte{})
		assert.Equal(t, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", hash)
	})

	t.Run("non-empty body", func(t *testing.T) {
		hash := ComputePayloadHash([]byte("hello"))
		assert.Equal(t, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", hash)
	})

	t.Run("deterministic", func(t *testing.T) {
		h1 := ComputePayloadHash([]byte("test"))
		h2 := ComputePayloadHash([]byte("test"))
		assert.Equal(t, h1, h2)
	})
}

// --- ParseAWSDate ---

func TestParseAWSDate(t *testing.T) {
	t.Run("valid date", func(t *testing.T) {
		ts, err := ParseAWSDate("20260410T120000Z")
		require.NoError(t, err)
		assert.Equal(t, 2026, ts.Year())
		assert.Equal(t, time.Month(4), ts.Month())
		assert.Equal(t, 10, ts.Day())
		assert.Equal(t, 12, ts.Hour())
	})

	t.Run("invalid date", func(t *testing.T) {
		_, err := ParseAWSDate("not-a-date")
		require.Error(t, err)
	})
}

// --- ReadRequestBody ---

func TestReadRequestBody(t *testing.T) {
	t.Run("normal body", func(t *testing.T) {
		r := httptest.NewRequest("POST", "/", bytes.NewBufferString("hello world"))
		body, err := ReadRequestBody(r, 1024)
		require.NoError(t, err)
		assert.Equal(t, "hello world", string(body))
	})

	t.Run("nil body", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/", nil)
		r.Body = nil
		body, err := ReadRequestBody(r, 1024)
		require.NoError(t, err)
		assert.Nil(t, body)
	})

	t.Run("exceeds max size", func(t *testing.T) {
		r := httptest.NewRequest("POST", "/", bytes.NewBufferString("hello world"))
		_, err := ReadRequestBody(r, 5)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "exceeds maximum size")
	})

	t.Run("zero max size - no limit", func(t *testing.T) {
		r := httptest.NewRequest("POST", "/", bytes.NewBufferString("hello world"))
		body, err := ReadRequestBody(r, 0)
		require.NoError(t, err)
		assert.Equal(t, "hello world", string(body))
	})
}

// --- RestoreRequestBody ---

func TestRestoreRequestBody(t *testing.T) {
	t.Run("non-empty body", func(t *testing.T) {
		r := httptest.NewRequest("POST", "/", nil)
		RestoreRequestBody(r, []byte("restored"))
		got, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		assert.Equal(t, "restored", string(got))
		assert.Equal(t, int64(8), r.ContentLength)
	})

	t.Run("empty body", func(t *testing.T) {
		r := httptest.NewRequest("POST", "/", nil)
		RestoreRequestBody(r, []byte{})
		assert.Nil(t, r.Body)
		assert.Equal(t, int64(0), r.ContentLength)
	})
}

// --- IsAWSChunked ---

func TestIsAWSChunked(t *testing.T) {
	t.Run("aws-chunked", func(t *testing.T) {
		r, _ := http.NewRequest("PUT", "/", nil)
		r.Header.Set("Content-Encoding", "aws-chunked")
		assert.True(t, IsAWSChunked(r))
	})

	t.Run("gzip and aws-chunked", func(t *testing.T) {
		r, _ := http.NewRequest("PUT", "/", nil)
		r.Header.Set("Content-Encoding", "gzip, aws-chunked")
		assert.True(t, IsAWSChunked(r))
	})

	t.Run("no content-encoding", func(t *testing.T) {
		r, _ := http.NewRequest("PUT", "/", nil)
		assert.False(t, IsAWSChunked(r))
	})

	t.Run("gzip only", func(t *testing.T) {
		r, _ := http.NewRequest("PUT", "/", nil)
		r.Header.Set("Content-Encoding", "gzip")
		assert.False(t, IsAWSChunked(r))
	})
}

// --- DecodeAWSChunkedBody ---

func TestDecodeAWSChunkedBody(t *testing.T) {
	t.Run("single chunk", func(t *testing.T) {
		body := []byte("5;chunk-signature=aaa\r\nhello\r\n0;chunk-signature=bbb\r\n\r\n")
		decoded, err := DecodeAWSChunkedBody(body)
		require.NoError(t, err)
		assert.Equal(t, "hello", string(decoded))
	})

	t.Run("multiple chunks", func(t *testing.T) {
		body := []byte("5;chunk-signature=aaa\r\nhello\r\n6;chunk-signature=bbb\r\n world\r\n0;chunk-signature=ccc\r\n\r\n")
		decoded, err := DecodeAWSChunkedBody(body)
		require.NoError(t, err)
		assert.Equal(t, "hello world", string(decoded))
	})

	t.Run("empty body - zero chunk", func(t *testing.T) {
		body := []byte("0;chunk-signature=aaa\r\n\r\n")
		decoded, err := DecodeAWSChunkedBody(body)
		require.NoError(t, err)
		assert.Empty(t, decoded)
	})

	t.Run("invalid hex size", func(t *testing.T) {
		body := []byte("ZZ;chunk-signature=aaa\r\ndata\r\n")
		_, err := DecodeAWSChunkedBody(body)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid chunk size")
	})

	t.Run("truncated data", func(t *testing.T) {
		body := []byte("a;chunk-signature=aaa\r\nshort\r\n")
		_, err := DecodeAWSChunkedBody(body)
		require.Error(t, err)
	})
}

// --- RemoveAWSChunkedEncoding ---

func TestRemoveAWSChunkedEncoding(t *testing.T) {
	t.Run("only aws-chunked", func(t *testing.T) {
		r, _ := http.NewRequest("PUT", "/", nil)
		r.Header.Set("Content-Encoding", "aws-chunked")
		RemoveAWSChunkedEncoding(r)
		assert.Empty(t, r.Header.Get("Content-Encoding"))
	})

	t.Run("aws-chunked with gzip", func(t *testing.T) {
		r, _ := http.NewRequest("PUT", "/", nil)
		r.Header.Set("Content-Encoding", "gzip, aws-chunked")
		RemoveAWSChunkedEncoding(r)
		assert.Equal(t, "gzip", r.Header.Get("Content-Encoding"))
	})

	t.Run("no content-encoding", func(t *testing.T) {
		r, _ := http.NewRequest("PUT", "/", nil)
		RemoveAWSChunkedEncoding(r)
		assert.Empty(t, r.Header.Get("Content-Encoding"))
	})
}

// --- NormalizeRequest ---

func TestNormalizeRequest(t *testing.T) {
	log := createTestLogger()

	t.Run("strips hop-by-hop headers", func(t *testing.T) {
		r, _ := http.NewRequest("GET", "/", nil)
		r.Header.Set("Connection", "keep-alive")
		r.Header.Set("Keep-Alive", "timeout=5")
		r.Header.Set("Transfer-Encoding", "chunked")
		r.Header.Set("X-Custom", "preserved")

		NormalizeRequest(log, r, []byte{})

		assert.Empty(t, r.Header.Get("Connection"))
		assert.Empty(t, r.Header.Get("Keep-Alive"))
		assert.Empty(t, r.Header.Get("Transfer-Encoding"))
		assert.Equal(t, "preserved", r.Header.Get("X-Custom"))
	})

	t.Run("strips proxy headers", func(t *testing.T) {
		r, _ := http.NewRequest("GET", "/", nil)
		r.Header.Set("X-Forwarded-For", "1.2.3.4")
		r.Header.Set("X-Real-Ip", "1.2.3.4")
		r.Header.Set("Forwarded", "for=1.2.3.4")

		NormalizeRequest(log, r, []byte{})

		assert.Empty(t, r.Header.Get("X-Forwarded-For"))
		assert.Empty(t, r.Header.Get("X-Real-Ip"))
		assert.Empty(t, r.Header.Get("Forwarded"))
	})

	t.Run("strips trailer headers when X-Amz-Trailer present", func(t *testing.T) {
		r, _ := http.NewRequest("PUT", "/", nil)
		r.Header.Set("X-Amz-Trailer", "x-amz-checksum-crc32")
		r.Header.Set("X-Amz-Sdk-Checksum-Algorithm", "CRC32")
		r.Header.Set("X-Amz-Checksum-Crc32", "abc123")

		NormalizeRequest(log, r, []byte{})

		assert.Empty(t, r.Header.Get("X-Amz-Trailer"))
		assert.Empty(t, r.Header.Get("X-Amz-Sdk-Checksum-Algorithm"))
		assert.Empty(t, r.Header.Get("X-Amz-Checksum-Crc32"))
	})
}

// --- ResignRequest + VerifyIncomingSignature round-trip ---

func TestResignAndVerify(t *testing.T) {
	log := createTestLogger()
	s3Opts := []func(*v4.SignerOptions){
		func(o *v4.SignerOptions) { o.DisableURIPathEscaping = true },
	}
	signer := v4.NewSigner(s3Opts...)

	creds := aws.Credentials{
		AccessKeyID:     "SCWXXXXXXXXXXXXXXXXX",
		SecretAccessKey: "test-secret-key-uuid",
	}

	body := []byte(`{"key":"value"}`)

	r, _ := http.NewRequest("PUT", "https://s3.fr-par.scw.cloud/my-bucket/test.txt", bytes.NewReader(body))
	r.Header.Set("Host", "s3.fr-par.scw.cloud")

	err := ResignRequest(context.Background(), signer, r, creds, "s3", "fr-par", body)
	require.NoError(t, err)

	assert.NotEmpty(t, r.Header.Get("Authorization"))
	assert.Contains(t, r.Header.Get("Authorization"), "AWS4-HMAC-SHA256")
	assert.NotEmpty(t, r.Header.Get("X-Amz-Content-Sha256"))
	assert.NotEmpty(t, r.Header.Get("X-Amz-Date"))

	valid, err := VerifyIncomingSignature(log, s3Opts, r, body, creds, "s3", "fr-par")
	require.NoError(t, err)
	assert.True(t, valid)
}

func TestVerifyIncomingSignature_Mismatch(t *testing.T) {
	log := createTestLogger()
	s3Opts := []func(*v4.SignerOptions){
		func(o *v4.SignerOptions) { o.DisableURIPathEscaping = true },
	}
	signer := v4.NewSigner(s3Opts...)

	signingCreds := aws.Credentials{
		AccessKeyID:     "SCWXXXXXXXXXXXXXXXXX",
		SecretAccessKey: "correct-secret-key-value",
	}

	body := []byte("test body")

	r, _ := http.NewRequest("PUT", "https://s3.fr-par.scw.cloud/bucket/key", bytes.NewReader(body))
	r.Header.Set("Host", "s3.fr-par.scw.cloud")

	err := ResignRequest(context.Background(), signer, r, signingCreds, "s3", "fr-par", body)
	require.NoError(t, err)

	// Verify with correct credentials should succeed
	valid, err := VerifyIncomingSignature(log, s3Opts, r, body, signingCreds, "s3", "fr-par")
	require.NoError(t, err)
	require.True(t, valid, "correct creds must verify")

	// Verify with wrong credentials should fail
	wrongCreds := aws.Credentials{
		AccessKeyID:     "SCWXXXXXXXXXXXXXXXXX",
		SecretAccessKey: "wrong-secret-key-value",
	}
	valid, err = VerifyIncomingSignature(log, s3Opts, r, body, wrongCreds, "s3", "fr-par")
	require.NoError(t, err)
	assert.False(t, valid, "wrong secret should produce signature mismatch")
}

// --- ForwardDirect ---

func TestForwardDirect(t *testing.T) {
	log := createTestLogger()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "custom-value", r.Header.Get("X-Custom"))
		w.Header().Set("X-Response", "ok")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("response body"))
	}))
	defer upstream.Close()

	r, _ := http.NewRequest("GET", upstream.URL+"/test", nil)
	r.Header.Set("X-Custom", "custom-value")
	r.RequestURI = ""

	rec := httptest.NewRecorder()
	ForwardDirect(log, rec, r, []byte{}, upstream.Client().Transport)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "ok", rec.Header().Get("X-Response"))
	assert.Contains(t, rec.Body.String(), "response body")
}

func TestForwardDirect_UpstreamError(t *testing.T) {
	log := createTestLogger()

	// Use a URL that won't connect
	r, _ := http.NewRequest("GET", "http://127.0.0.1:1/unreachable", nil)
	r.RequestURI = ""

	rec := httptest.NewRecorder()
	ForwardDirect(log, rec, r, []byte{}, http.DefaultTransport)

	assert.Equal(t, http.StatusBadGateway, rec.Code)
}

// --- ForwardDirectFiltered ---

func serveBody(t *testing.T, status int, contentType, body string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if contentType != "" {
			w.Header().Set("Content-Type", contentType)
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
}

func TestForwardDirectFiltered_TransformsBodyAndFixesLength(t *testing.T) {
	log := createTestLogger()
	upstream := serveBody(t, http.StatusOK, "application/json", `{"tools":["get_x","delete_x"]}`)
	defer upstream.Close()

	r, _ := http.NewRequest("POST", upstream.URL+"/gateway", nil)
	r.RequestURI = ""
	rec := httptest.NewRecorder()

	modify := func(ct string, body []byte) ([]byte, error) {
		assert.Equal(t, "application/json", ct)
		return []byte("FILTERED"), nil
	}
	ForwardDirectFiltered(log, rec, r, []byte{}, upstream.Client().Transport, 1<<20, modify)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "FILTERED", rec.Body.String())
	assert.Equal(t, "8", rec.Header().Get("Content-Length"))
}

func TestForwardDirectFiltered_NilModifyVerbatim(t *testing.T) {
	log := createTestLogger()
	upstream := serveBody(t, http.StatusOK, "application/json", `{"tools":["delete_x"]}`)
	defer upstream.Close()

	r, _ := http.NewRequest("POST", upstream.URL+"/gateway", nil)
	r.RequestURI = ""
	rec := httptest.NewRecorder()

	ForwardDirectFiltered(log, rec, r, []byte{}, upstream.Client().Transport, 1<<20, nil)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "delete_x")
}

func TestForwardDirectFiltered_NonSuccessSkipsModify(t *testing.T) {
	log := createTestLogger()
	upstream := serveBody(t, http.StatusForbidden, "application/json", `{"error":"denied"}`)
	defer upstream.Close()

	r, _ := http.NewRequest("POST", upstream.URL+"/gateway", nil)
	r.RequestURI = ""
	rec := httptest.NewRecorder()

	modify := func(ct string, body []byte) ([]byte, error) {
		t.Fatalf("modify must not run for a non-2xx response")
		return nil, nil
	}
	ForwardDirectFiltered(log, rec, r, []byte{}, upstream.Client().Transport, 1<<20, modify)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Contains(t, rec.Body.String(), "denied")
}

func TestForwardDirectFiltered_ModifyErrorFailsClosed(t *testing.T) {
	log := createTestLogger()
	upstream := serveBody(t, http.StatusOK, "application/json", `{"tools":[]}`)
	defer upstream.Close()

	r, _ := http.NewRequest("POST", upstream.URL+"/gateway", nil)
	r.RequestURI = ""
	rec := httptest.NewRecorder()

	modify := func(ct string, body []byte) ([]byte, error) {
		return nil, assert.AnError
	}
	ForwardDirectFiltered(log, rec, r, []byte{}, upstream.Client().Transport, 1<<20, modify)

	assert.Equal(t, http.StatusBadGateway, rec.Code)
}

func TestForwardDirectFiltered_OversizeFailsClosed(t *testing.T) {
	log := createTestLogger()
	upstream := serveBody(t, http.StatusOK, "application/json", `{"tools":["a","b","c","d","e"]}`)
	defer upstream.Close()

	r, _ := http.NewRequest("POST", upstream.URL+"/gateway", nil)
	r.RequestURI = ""
	rec := httptest.NewRecorder()

	called := false
	modify := func(ct string, body []byte) ([]byte, error) {
		called = true
		return body, nil
	}
	ForwardDirectFiltered(log, rec, r, []byte{}, upstream.Client().Transport, 5, modify)

	assert.Equal(t, http.StatusBadGateway, rec.Code)
	assert.False(t, called, "modify must not run when the body exceeds the cap")
}

// --- Failures the forward raises itself ---

// roundTripFunc is an http.RoundTripper made of a function.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// untilDone is an upstream that never answers: it waits for the request's
// context to end.
var untilDone = roundTripFunc(func(r *http.Request) (*http.Response, error) {
	<-r.Context().Done()
	return nil, r.Context().Err()
})

// A mount's timeout passing before the upstream answers is a 504: the client
// is still waiting, and written nothing it would read an empty 200.
func TestForwardDirect_TimeoutAnswers504(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	r, _ := http.NewRequestWithContext(ctx, "GET", "http://upstream.test/", nil)

	rec := httptest.NewRecorder()
	ForwardDirect(createTestLogger(), rec, r, []byte{}, untilDone)

	assert.Equal(t, http.StatusGatewayTimeout, rec.Code)
	assert.Equal(t, "Gateway Timeout\n", rec.Body.String())
}

// A client that went away gets nothing written: no one is reading.
func TestForwardDirect_ClientGoneWritesNothing(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r, _ := http.NewRequestWithContext(ctx, "GET", "http://upstream.test/", nil)

	rec := httptest.NewRecorder()
	ForwardDirect(createTestLogger(), rec, r, []byte{}, untilDone)

	assert.Empty(t, rec.Header())
	assert.Zero(t, rec.Body.Len())
}

// forwardFailures are the failures the forward raises itself, each set up
// for ForwardDirectOpts, with the status and text http.Error answers it with.
func forwardFailures(t *testing.T) []struct {
	name   string
	run    func(w http.ResponseWriter, opts ForwardOptions)
	status int
	text   string
} {
	t.Helper()
	ok := serveBody(t, http.StatusOK, "application/json", `{"tools":["a","b"]}`)
	t.Cleanup(ok.Close)
	// cut promises a longer body than it sends, so reading it fails.
	cut := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "100")
		_, _ = w.Write([]byte(`{"tools":`))
	}))
	t.Cleanup(cut.Close)
	post := func(ctx context.Context, url string) *http.Request {
		r, _ := http.NewRequestWithContext(ctx, "POST", url, nil)
		return r
	}
	return []struct {
		name   string
		run    func(w http.ResponseWriter, opts ForwardOptions)
		status int
		text   string
	}{
		{"request cannot be built", func(w http.ResponseWriter, opts ForwardOptions) {
			r := post(context.Background(), ok.URL)
			r.Method = "BAD METHOD"
			ForwardDirectOpts(createTestLogger(), w, r, []byte{}, ok.Client().Transport, opts)
		}, http.StatusInternalServerError, "Internal server error"},
		{"upstream unreachable", func(w http.ResponseWriter, opts ForwardOptions) {
			ForwardDirectOpts(createTestLogger(), w, post(context.Background(), "http://127.0.0.1:1/"), []byte{}, http.DefaultTransport, opts)
		}, http.StatusBadGateway, "Bad Gateway"},
		{"upstream too slow", func(w http.ResponseWriter, opts ForwardOptions) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
			defer cancel()
			ForwardDirectOpts(createTestLogger(), w, post(ctx, "http://upstream.test/"), []byte{}, untilDone, opts)
		}, http.StatusGatewayTimeout, "Gateway Timeout"},
		{"filtered body over the cap", func(w http.ResponseWriter, opts ForwardOptions) {
			opts.MaxBody = 5
			opts.Modify = func(_ string, b []byte) ([]byte, error) { return b, nil }
			ForwardDirectOpts(createTestLogger(), w, post(context.Background(), ok.URL), []byte{}, ok.Client().Transport, opts)
		}, http.StatusBadGateway, "Bad Gateway"},
		{"filtered body cut short", func(w http.ResponseWriter, opts ForwardOptions) {
			opts.Modify = func(_ string, b []byte) ([]byte, error) { return b, nil }
			ForwardDirectOpts(createTestLogger(), w, post(context.Background(), cut.URL), []byte{}, cut.Client().Transport, opts)
		}, http.StatusBadGateway, "Bad Gateway"},
		{"filtered body cannot be transformed", func(w http.ResponseWriter, opts ForwardOptions) {
			opts.Modify = func(string, []byte) ([]byte, error) { return nil, assert.AnError }
			ForwardDirectOpts(createTestLogger(), w, post(context.Background(), ok.URL), []byte{}, ok.Client().Transport, opts)
		}, http.StatusBadGateway, "Bad Gateway"},
	}
}

// Without OnError every failure is answered as it always was, by http.Error —
// what every caller of ForwardDirect and ForwardDirectFiltered still gets.
func TestForwardDirectOpts_NoOnErrorKeepsHTTPError(t *testing.T) {
	for _, f := range forwardFailures(t) {
		t.Run(f.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			f.run(rec, ForwardOptions{})

			want := httptest.NewRecorder()
			http.Error(want, f.text, f.status)
			assert.Equal(t, want.Code, rec.Code)
			assert.Equal(t, want.Header(), rec.Header())
			assert.Equal(t, want.Body.String(), rec.Body.String())
		})
	}
}

// With OnError, every failure is handed to it instead, with the status and
// text http.Error would have used, and the forward writes nothing itself.
func TestForwardDirectOpts_OnError(t *testing.T) {
	for _, f := range forwardFailures(t) {
		t.Run(f.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			calls := 0
			f.run(rec, ForwardOptions{OnError: func(w http.ResponseWriter, status int, text string) {
				calls++
				assert.Equal(t, f.status, status)
				assert.Equal(t, f.text, text)
				w.WriteHeader(http.StatusTeapot)
			}})

			assert.Equal(t, 1, calls)
			assert.Equal(t, http.StatusTeapot, rec.Code)
			assert.Zero(t, rec.Body.Len(), "the forward must not write the answer itself")
		})
	}
}
