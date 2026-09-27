package remotesign

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// capSignServer is a transit sign endpoint that is safe to hit concurrently. It signs
// with one RSA key, can be told to refuse, and counts the connections it saw close.
type capSignServer struct {
	key    *rsa.PrivateKey
	url    string
	status atomic.Int32 // non-zero: refuse every sign with this status
	closed atomic.Int32

	mu     sync.Mutex
	tokens map[string]int // X-Vault-Token -> sign calls
}

func newCapSignServer(t *testing.T) *capSignServer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	s := &capSignServer{key: key, tokens: map[string]int{}}

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if !strings.HasPrefix(r.URL.Path, "/v1/transit/sign/") {
			http.Error(w, "unexpected "+r.URL.Path, http.StatusNotFound)
			return
		}
		s.mu.Lock()
		s.tokens[r.Header.Get("X-Vault-Token")]++
		s.mu.Unlock()
		if st := s.status.Load(); st != 0 {
			w.WriteHeader(int(st))
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"errors": []string{"refused"}})
			return
		}
		var body map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		digest, _ := base64.StdEncoding.DecodeString(body["input"].(string))
		sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		ver, _ := asInt(body["key_version"])
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": map[string]interface{}{
			"signature":   fmt.Sprintf("vault:v%d:%s", ver, base64.StdEncoding.EncodeToString(sig)),
			"key_version": ver,
		}})
	}))
	srv.Config.ConnState = func(_ net.Conn, st http.ConnState) {
		if st == http.StateClosed {
			s.closed.Add(1)
		}
	}
	srv.Start()
	t.Cleanup(srv.Close)
	s.url = srv.URL
	return s
}

func (s *capSignServer) signsWith(token string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tokens[token]
}

// transitCapabilityPayload is a capability exactly as v0.20.0's producer wrote it,
// by literal key names — the released wire format a cached capability may still hold.
func transitCapabilityPayload(addr string, over map[string]string) map[string]string {
	data := map[string]string{
		"kms_backend":         "transit",
		"vault_token":         "hvs.capability",
		"vault_address":       addr,
		"transit_mount":       "transit",
		"transit_key":         "client-assertion",
		"transit_key_version": "2",
		"signing_alg":         "RS256",
		"kid":                 "client-assertion-v2",
		"client_id":           "warden-gateway",
		"token_expires_at":    "2031-01-02T03:04:05Z",
	}
	for k, v := range over {
		if v == "" {
			delete(data, k)
			continue
		}
		data[k] = v
	}
	return data
}

func TestDecodeCapability_ReleasedPayload(t *testing.T) {
	c, err := DecodeCapability(transitCapabilityPayload("https://kms.example", map[string]string{"vault_namespace": "team-a"}))
	require.NoError(t, err)
	assert.Equal(t, BackendTypeTransit, c.Backend)
	assert.Equal(t, KeyRef{KeyName: "client-assertion", Version: "2", Alg: "RS256"}, c.Ref)
	assert.Equal(t, "client-assertion-v2", c.Kid)
	assert.Equal(t, time.Date(2031, 1, 2, 3, 4, 5, 0, time.UTC), c.ExpiresAt)
	assert.Equal(t, transitCoords{
		token: "hvs.capability", address: "https://kms.example", namespace: "team-a", mount: "transit",
	}, c.coords)

	// An unreadable expiry costs only the preflight.
	c, err = DecodeCapability(transitCapabilityPayload("https://kms.example", map[string]string{"token_expires_at": "soon"}))
	require.NoError(t, err)
	assert.True(t, c.ExpiresAt.IsZero())
}

// TestEncodeTransitCapability_RoundTrips: what a producer writes is exactly what a
// consumer reads, and it is the released key set, byte for byte.
func TestEncodeTransitCapability_RoundTrips(t *testing.T) {
	exp := time.Date(2031, 1, 2, 3, 4, 5, 0, time.FixedZone("x", 3600))
	for _, ns := range []string{"", "team-a"} {
		enc := EncodeTransitCapability(TransitCapability{
			Token: "hvs.t", Address: "https://kms.example", Namespace: ns, Mount: "transit",
			Ref: KeyRef{KeyName: "k", Version: "7", Alg: "ES256"}, ExpiresAt: exp,
		})
		want := map[string]interface{}{
			"kms_backend": "transit", "vault_token": "hvs.t", "vault_address": "https://kms.example",
			"transit_mount": "transit", "transit_key": "k", "transit_key_version": "7",
			"signing_alg": "ES256", "token_expires_at": "2031-01-02T02:04:05Z",
		}
		if ns != "" {
			want["vault_namespace"] = ns
		}
		assert.Equal(t, want, enc, "namespace %q", ns)

		data := map[string]string{}
		for k, v := range enc {
			data[k] = v.(string)
		}
		c, err := DecodeCapability(data)
		require.NoError(t, err)
		assert.Equal(t, KeyRef{KeyName: "k", Version: "7", Alg: "ES256"}, c.Ref)
		assert.True(t, exp.Equal(c.ExpiresAt))
		assert.Equal(t, ns, c.coords.(transitCoords).namespace)
	}
}

func TestDecodeCapability_Refusals(t *testing.T) {
	cases := []struct {
		name string
		over map[string]string
		msg  string
		want error
	}{
		{"missing backend", map[string]string{"kms_backend": ""}, "kms_backend", ErrCapabilityIncomplete},
		{"missing token", map[string]string{"vault_token": ""}, "vault_token", ErrCapabilityIncomplete},
		{"missing address", map[string]string{"vault_address": ""}, "vault_address", ErrCapabilityIncomplete},
		{"missing mount", map[string]string{"transit_mount": ""}, "transit_mount", ErrCapabilityIncomplete},
		{"missing key", map[string]string{"transit_key": ""}, "transit_key", ErrCapabilityIncomplete},
		{"missing version", map[string]string{"transit_key_version": ""}, "transit_key_version", ErrCapabilityIncomplete},
		{"missing alg", map[string]string{"signing_alg": ""}, "signing_alg", ErrCapabilityIncomplete},
		{"zero version", map[string]string{"transit_key_version": "0"}, "unusable key version", ErrCapabilityIncomplete},
		{"latest version", map[string]string{"transit_key_version": "latest"}, "unusable key version", ErrCapabilityIncomplete},
		{"unknown alg", map[string]string{"signing_alg": "PS256"}, "PS256", ErrCapabilityIncomplete},
		{"unknown backend", map[string]string{"kms_backend": "cloudkms"}, "cloudkms", ErrCapabilityUnsupported},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DecodeCapability(transitCapabilityPayload("https://kms.example", tc.over))
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.msg)
			assert.ErrorIs(t, err, tc.want)
			for _, other := range []error{ErrCapabilityIncomplete, ErrCapabilityUnsupported, ErrCapabilityRejected} {
				if other != tc.want {
					assert.NotErrorIs(t, err, other, "carries exactly one verdict")
				}
			}
		})
	}
}

// TestReservedCapabilityKeys_Transit: the set a producer's passthrough may not
// overwrite is exactly the one the transit producer refused before it moved here.
// kid and client_id are absent on purpose: they travel through the passthrough.
func TestReservedCapabilityKeys_Transit(t *testing.T) {
	want := map[string]struct{}{
		"kms_backend": {}, "vault_token": {}, "vault_address": {}, "vault_namespace": {},
		"transit_mount": {}, "transit_key": {}, "transit_key_version": {},
		"signing_alg": {}, "token_expires_at": {},
	}
	assert.Equal(t, want, ReservedCapabilityKeys(BackendTypeTransit))
	assert.Nil(t, ReservedCapabilityKeys("cloudkms"))
}

func TestCapabilitySigners_SignsWithTheCapabilityToken(t *testing.T) {
	srv := newCapSignServer(t)
	signers := NewCapabilitySigners(nil, CapabilityOptions{})
	defer signers.Close()

	c, err := DecodeCapability(transitCapabilityPayload(srv.url, nil))
	require.NoError(t, err)
	jws, err := signers.SignJWS(context.Background(), c, map[string]string{"kid": c.Kid}, map[string]interface{}{"iss": "x"})
	require.NoError(t, err)
	verifyRS256(t, &srv.key.PublicKey, jws)
	assert.Equal(t, 1, srv.signsWith("hvs.capability"))

	_, err = signers.SignJWS(context.Background(), &Capability{Backend: "cloudkms"}, nil, nil)
	assert.ErrorIs(t, err, ErrCapabilityUnsupported)
}

// TestCapabilitySigners_Classify: a refusal the store answered exposes its status
// through HTTPStatus alone — the only thing a caller outside this package can rely on
// for a backend it knows nothing about — and says whether a new capability would help.
func TestCapabilitySigners_Classify(t *testing.T) {
	// The client retries a 5xx and a refused connection with backoff; the verdict is
	// the same on the last attempt as on the first, so skip the wait.
	t.Setenv("VAULT_MAX_RETRIES", "0")
	cases := []struct {
		status   int
		rejected bool
	}{
		{http.StatusForbidden, true},
		{http.StatusUnauthorized, true},
		{http.StatusBadRequest, true},
		{http.StatusInternalServerError, false},
	}
	for _, tc := range cases {
		t.Run(http.StatusText(tc.status), func(t *testing.T) {
			srv := newCapSignServer(t)
			srv.status.Store(int32(tc.status))
			signers := NewCapabilitySigners(nil, CapabilityOptions{})
			defer signers.Close()

			c, err := DecodeCapability(transitCapabilityPayload(srv.url, nil))
			require.NoError(t, err)
			_, err = signers.SignJWS(context.Background(), c, nil, map[string]interface{}{"iss": "x"})
			require.Error(t, err)
			assert.Equal(t, tc.rejected, errors.Is(err, ErrCapabilityRejected))

			var reported interface{ HTTPStatus() int }
			require.True(t, errors.As(err, &reported), "no HTTPStatus in %v", err)
			assert.Equal(t, tc.status, reported.HTTPStatus())
		})
	}

	t.Run("unreachable", func(t *testing.T) {
		signers := NewCapabilitySigners(nil, CapabilityOptions{})
		c, err := DecodeCapability(transitCapabilityPayload("http://127.0.0.1:1", nil))
		require.NoError(t, err)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err = signers.SignJWS(ctx, c, nil, map[string]interface{}{"iss": "x"})
		require.Error(t, err)
		assert.NotErrorIs(t, err, ErrCapabilityRejected, "a new capability cannot mend a network")
		var reported interface{ HTTPStatus() int }
		assert.False(t, errors.As(err, &reported), "nothing answered, so there is no status")
	})
}

// TestCapabilitySigners_CloseAlongsideSigning: Close drops idle pooled connections and
// may run while signatures are in flight; signing afterwards reconnects. Under -race this
// also checks the pool and the per-signature clones share nothing mutable.
func TestCapabilitySigners_CloseAlongsideSigning(t *testing.T) {
	srv := newCapSignServer(t)
	signers := NewCapabilitySigners(nil, CapabilityOptions{})

	const n = 16
	var wg sync.WaitGroup
	errs := make([]error, n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c, err := DecodeCapability(transitCapabilityPayload(srv.url, map[string]string{
				"vault_token": fmt.Sprintf("hvs.token-%02d", i),
			}))
			if err != nil {
				errs[i] = err
				return
			}
			<-start
			for j := 0; j < 3; j++ {
				if _, err := signers.SignJWS(context.Background(), c, nil, map[string]interface{}{"i": i}); err != nil {
					errs[i] = err
					return
				}
			}
		}(i)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		for j := 0; j < 5; j++ {
			signers.Close()
		}
	}()
	close(start)
	wg.Wait()
	for i, err := range errs {
		require.NoError(t, err, "signer %d", i)
		assert.Equal(t, 3, srv.signsWith(fmt.Sprintf("hvs.token-%02d", i)), "each capability signed with its own token")
	}

	// One more signature leaves a connection idle, whatever the concurrent Closes did.
	c, err := DecodeCapability(transitCapabilityPayload(srv.url, nil))
	require.NoError(t, err)
	_, err = signers.SignJWS(context.Background(), c, nil, map[string]interface{}{"iss": "x"})
	require.NoError(t, err)
	// Let any close the earlier Closes started land, so the count below moves only
	// for this one.
	time.Sleep(50 * time.Millisecond)
	before := srv.closed.Load()

	// Close drops it...
	signers.Close()
	require.Eventually(t, func() bool { return srv.closed.Load() > before }, 2*time.Second, 10*time.Millisecond,
		"Close must close the pool's idle connections")

	// ...and signing still works afterwards.
	jws, err := signers.SignJWS(context.Background(), c, nil, map[string]interface{}{"iss": "x"})
	require.NoError(t, err)
	verifyRS256(t, &srv.key.PublicKey, jws)
}

// countingTransport counts the requests that travel through it.
type countingTransport struct {
	next  http.RoundTripper
	count atomic.Int32
}

func (c *countingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	c.count.Add(1)
	return c.next.RoundTrip(r)
}

// TestCapabilitySigners_ConsumerTransport: a consumer's client lends its transport to
// signing requests, but not its redirect policy — where a capability's token goes is
// decided by the signing client alone.
func TestCapabilitySigners_ConsumerTransport(t *testing.T) {
	srv := newCapSignServer(t)
	ct := &countingTransport{next: http.DefaultTransport}
	followed := false
	consumer := &http.Client{
		Transport: ct,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			followed = true
			return nil
		},
	}
	signers := NewCapabilitySigners(nil, CapabilityOptions{HTTPClient: consumer})
	defer signers.Close()

	c, err := DecodeCapability(transitCapabilityPayload(srv.url, nil))
	require.NoError(t, err)
	jws, err := signers.SignJWS(context.Background(), c, nil, map[string]interface{}{"iss": "x"})
	require.NoError(t, err)
	verifyRS256(t, &srv.key.PublicKey, jws)
	assert.Equal(t, int32(1), ct.count.Load(), "the signature travelled through the consumer's transport")

	// A store that redirects. The consumer's policy is never consulted; the signing
	// client follows a single store redirect itself, as it did before the consumer
	// could lend a transport, so the redirected signature lands once.
	redirect := httptest.NewServer(http.RedirectHandler(srv.url+"/v1/transit/sign/client-assertion", http.StatusFound))
	defer redirect.Close()
	c, err = DecodeCapability(transitCapabilityPayload(redirect.URL, nil))
	require.NoError(t, err)
	_, err = signers.SignJWS(context.Background(), c, nil, map[string]interface{}{"iss": "x"})
	require.NoError(t, err)
	assert.False(t, followed, "the consumer's redirect policy must not apply to a capability")
	assert.Equal(t, 2, srv.signsWith("hvs.capability"), "one direct signature, one after the store's redirect")
}

func verifyRS256(t *testing.T, pub *rsa.PublicKey, jws string) {
	t.Helper()
	parts := strings.Split(jws, ".")
	require.Len(t, parts, 3)
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	require.NoError(t, err)
	h := crypto.SHA256.New()
	h.Write([]byte(parts[0] + "." + parts[1]))
	require.NoError(t, rsa.VerifyPKCS1v15(pub, crypto.SHA256, h.Sum(nil), sig))
}
