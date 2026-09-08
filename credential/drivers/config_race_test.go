package drivers

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests cover the driver side of source-config rotation: a rotation replaces
// the config map while mints are still reading it. Run under -race — the detector
// reports on the unguarded versions and is quiet on the guarded ones. Only the
// generation-coherence test asserts a value; the rest exist for the detector.

// TestAzureDriver_SourceCredsNeverMixesGenerations is the one case where locking each
// read individually is not enough.
//
// Acquiring a token needs tenant, client id and secret together. Read one at a time,
// a rotation landing between two of them pairs a client id with a secret from another
// generation — a credential that never existed at the provider, whose failure reads
// like a bad stored secret rather than a torn read. Each value here carries its
// generation so a mixed triple is detectable.
func TestAzureDriver_SourceCredsNeverMixesGenerations(t *testing.T) {
	driver := newTestAzureDriver()
	// Seed generation 0 so every value the readers see carries a generation; the
	// helper's defaults do not, and would read as a mixed triple.
	driver.credSource.Config = credential.NewConfig(map[string]string{
		"tenant_id":     "tenant-0",
		"client_id":     "client-0",
		"client_secret": "secret-0",
	})

	writerDone := make(chan struct{})
	stop := make(chan struct{})
	go func() {
		defer close(writerDone)
		for gen := 0; ; gen++ {
			select {
			case <-stop:
				return
			default:
			}
			cfg := map[string]string{
				"tenant_id":     fmt.Sprintf("tenant-%d", gen),
				"client_id":     fmt.Sprintf("client-%d", gen),
				"client_secret": fmt.Sprintf("secret-%d", gen),
			}
			// The swap CommitRotation performs, without its network round trip.
			driver.configMu.Lock()
			driver.credSource.Config = credential.NewConfig(cfg)
			driver.configMu.Unlock()
		}
	}()

	var readers sync.WaitGroup
	for i := 0; i < 4; i++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for j := 0; j < 20000; j++ {
				tenantID, clientID, clientSecret := driver.sourceCreds()
				tenantGen := strings.TrimPrefix(tenantID, "tenant-")
				clientGen := strings.TrimPrefix(clientID, "client-")
				secretGen := strings.TrimPrefix(clientSecret, "secret-")
				if tenantGen != clientGen || clientGen != secretGen {
					t.Errorf("torn credential read: tenant_id=%q client_id=%q client_secret=%q",
						tenantID, clientID, clientSecret)
					return
				}
			}
		}()
	}

	readers.Wait()
	close(stop)
	<-writerDone
}

// TestGitLabDriver_CommitRotationIsRaceFreeWithMints drives the real CommitRotation,
// whose config swap was the one write in this driver that took no lock at all, while
// readers do what the mint path does.
func TestGitLabDriver_CommitRotationIsRaceFreeWithMints(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":1,"name":"warden","active":true}`))
	}))
	defer server.Close()

	driver := newTestGitLabDriver("initial-token")
	driver.credSource.Config = driver.credSource.Config.With("gitlab_address", server.URL)
	driver.tokenCache = NewTokenCache()

	stop := make(chan struct{})
	var readers sync.WaitGroup
	for i := 0; i < 4; i++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				// Exactly what doGitLabRequest reads on every proxied request.
				_ = driver.getGitLabAddress()
				_ = driver.getPAT()
				_ = driver.getAuthMethod()
				_ = driver.isChained()
			}
		}()
	}

	for gen := 0; gen < 50; gen++ {
		newConfig := map[string]string{
			"gitlab_address":        server.URL,
			"auth_method":           "pat",
			"personal_access_token": fmt.Sprintf("rotated-token-%d", gen),
		}
		require.NoError(t, driver.CommitRotation(t.Context(), newConfig))
	}

	close(stop)
	readers.Wait()

	require.Equal(t, "rotated-token-49", driver.getPAT(),
		"the last committed token should be the one mints see")
}

// TestVaultDriver_ConfigReadsAreRaceFreeWithRotation covers the reads that ran bare
// while CommitRotation replaced the config under authMu.
//
// The values on the unguarded paths happen to be identical across a rotation, so this
// never produced a wrong credential — but an unsynchronized field write against
// unsynchronized reads is a data race whatever the values are, and equal values are
// not a guarantee the compiler or the memory model offers anything about.
func TestVaultDriver_ConfigReadsAreRaceFreeWithRotation(t *testing.T) {
	driver := &VaultDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeVault,
			Config: credential.NewConfig(map[string]string{
				"auth_method":   "approle",
				"vault_address": "https://vault.example.com",
				"role_id":       "role-0",
				"secret_id":     "secret-0",
				"approle_mount": "approle",
				"jwt_role":      "warden",
			}),
		},
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}

	stop := make(chan struct{})
	var readers sync.WaitGroup
	for i := 0; i < 4; i++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				_ = driver.getAuthMethod()
				_ = credential.GetString(driver.sourceConfig(), "vault_address", "")
			}
		}()
	}

	// The swap CommitRotation performs, without re-authenticating against a server.
	for gen := 0; gen < 2000; gen++ {
		newConfig := map[string]string{
			"auth_method":   "approle",
			"vault_address": "https://vault.example.com",
			"role_id":       fmt.Sprintf("role-%d", gen),
			"secret_id":     fmt.Sprintf("secret-%d", gen),
			"approle_mount": "approle",
			"jwt_role":      "warden",
		}
		driver.configMu.Lock()
		driver.credSource.Config = credential.NewConfig(newConfig)
		driver.configMu.Unlock()
	}

	close(stop)
	readers.Wait()
}

// TestKubernetesDriver_HTTPClientSwapIsRaceFree covers the client pointer, which a
// rotation replaces when the TLS settings change while requests are reading it.
func TestKubernetesDriver_HTTPClientSwapIsRaceFree(t *testing.T) {
	driver := &KubernetesDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeKubernetes,
			Config: credential.NewConfig(map[string]string{
				"kubernetes_url": "https://k8s.example.com",
				"token":          "initial",
			}),
		},
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}

	stop := make(chan struct{})
	var readers sync.WaitGroup
	for i := 0; i < 4; i++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				require.NotNil(t, driver.httpClientSnapshot())
			}
		}()
	}

	for gen := 0; gen < 2000; gen++ {
		client := &http.Client{Timeout: time.Duration(gen%10+1) * time.Second}
		driver.clientMu.Lock()
		driver.httpClient = client
		driver.clientMu.Unlock()
	}

	close(stop)
	readers.Wait()
}

// TestGitLabDriver_RequestUsesOneConfigGeneration asserts that a single request
// reads the address and the token from one snapshot.
//
// doGitLabRequest used to call getGitLabAddress, getAuthMethod and getPAT
// separately, taking three snapshots. Production rotation only ever replaces the
// token, so the mismatch stayed invisible — but that is a property of what rotation
// happens to touch today, not of the code. Both keys carry a generation here so the
// pairing is observable at all: each server accepts only its own token, and a
// request built from two generations arrives somewhere holding the wrong one.
func TestGitLabDriver_RequestUsesOneConfigGeneration(t *testing.T) {
	var mismatches int64

	newServer := func(wantToken string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("PRIVATE-TOKEN") != wantToken {
				atomic.AddInt64(&mismatches, 1)
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"id":1,"active":true}`))
		}))
	}

	serverA := newServer("token-a")
	defer serverA.Close()
	serverB := newServer("token-b")
	defer serverB.Close()

	driver := newTestGitLabDriver("token-a")
	driver.credSource.Config = credential.NewConfig(map[string]string{
		"gitlab_address":        serverA.URL,
		"auth_method":           "pat",
		"personal_access_token": "token-a",
	})
	driver.tokenCache = NewTokenCache()

	stop := make(chan struct{})
	var writer sync.WaitGroup
	writer.Add(1)
	go func() {
		defer writer.Done()
		generations := []credential.Config{
			credential.NewConfig(map[string]string{
				"gitlab_address": serverA.URL, "auth_method": "pat", "personal_access_token": "token-a",
			}),
			credential.NewConfig(map[string]string{
				"gitlab_address": serverB.URL, "auth_method": "pat", "personal_access_token": "token-b",
			}),
		}
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			driver.configMu.Lock()
			driver.credSource.Config = generations[i%2]
			driver.configMu.Unlock()
		}
	}()

	var callers sync.WaitGroup
	for i := 0; i < 4; i++ {
		callers.Add(1)
		go func() {
			defer callers.Done()
			for j := 0; j < 300; j++ {
				_, _, _ = driver.doGitLabRequest(t.Context(), http.MethodGet, "/api/v4/x", nil, nil)
			}
		}()
	}
	callers.Wait()
	close(stop)
	writer.Wait()

	assert.Zero(t, atomic.LoadInt64(&mismatches),
		"every request must send the token belonging to the address it was sent to")
}
