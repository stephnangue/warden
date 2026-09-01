//go:build e2e

package fullchain

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// A stand-in Elasticsearch cluster, shared by the chained and inline elastic
// suites so the two cannot drift apart in what they think a cluster does.
//
// It answers the three Security API calls the driver makes, and records what it
// was asked, because most of what these rows assert is not the response — it is
// which credential authenticated the call, and which keys were invalidated.

// elasticMintedFor derives the key the stub issues from the cluster key that
// authenticated the create. Deriving rather than returning a constant is what
// carries "which secret was spent" all the way to the header the gateway
// injects — a fixed value would look identical whichever key performed the call.
func elasticMintedFor(clusterKey string) string {
	return base64.StdEncoding.EncodeToString([]byte(elasticMintedKeyID + ":" + clusterKey))
}

const (
	// elasticMintedKeyID is the id the stub gives every per-spec key. Fixed, so a
	// row can name it without reading it back; the rotation keys below are the
	// ones that need to be told apart.
	elasticMintedKeyID = "fc-es-minted"

	// elasticRotatedKeyPrefix stamps keys minted for a source rotation, which the
	// stub tells apart by the metadata the driver sets. They need distinct ids: a
	// rotation row asserts that the OLD key was invalidated, which is only
	// meaningful if the new one is a different key.
	elasticRotatedKeyPrefix = "fc-es-rotated-"
)

// elasticCreate is one recorded key creation.
type elasticCreate struct {
	// ClusterKey is the credential that authenticated the create — the answer to
	// "which secret was spent".
	ClusterKey string
	// Body is the create request verbatim, so a row can assert the mint
	// parameters an operator set actually reached the cluster.
	Body map[string]interface{}
	// MintedID is the id the stub issued for it.
	MintedID string
}

// elasticClusterStub records what the driver asked of it. Every field is read
// under the mutex: rotation runs on the manager's own goroutine, so a row
// polling for its effects races the handler serving it.
type elasticClusterStub struct {
	*httptest.Server

	mu          sync.Mutex
	creates     []elasticCreate
	invalidated []string
	// batches records each invalidate call separately. A rotation invalidates
	// twice for different reasons — the sweep reclaims orphans, then cleanup
	// destroys the key just replaced — and only the grouping says which was
	// which.
	batches [][]string
	// queryable is what the sweep's listing reports. Primed by a row that wants
	// the sweep to find an abandoned key.
	queryable []string
	rotations int
}

func (s *elasticClusterStub) recordCreate(c elasticCreate) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.creates = append(s.creates, c)
}

// observed returns the cluster keys that authenticated a create, oldest first.
func (s *elasticClusterStub) observed() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	keys := make([]string, 0, len(s.creates))
	for _, c := range s.creates {
		keys = append(keys, c.ClusterKey)
	}
	return keys
}

func (s *elasticClusterStub) createdKeys() []elasticCreate {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]elasticCreate(nil), s.creates...)
}

func (s *elasticClusterStub) invalidatedKeys() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.invalidated...)
}

// invalidateBatches returns each invalidate call as its own slice, oldest first.
func (s *elasticClusterStub) invalidateBatches() [][]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([][]string(nil), s.batches...)
}

// reset clears the record. Standing a source and spec up already costs the
// cluster a create and a delete — spec validation test-mints and then releases
// the lease — so a row that means to count its own traffic starts from here.
func (s *elasticClusterStub) reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.creates = nil
	s.invalidated = nil
	s.batches = nil
}

// primeQueryable makes the sweep's listing report these key ids.
func (s *elasticClusterStub) primeQueryable(ids ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.queryable = ids
}

// sawInvalidated reports whether the given id has been invalidated yet.
func (s *elasticClusterStub) sawInvalidated(id string) bool {
	for _, got := range s.invalidatedKeys() {
		if got == id {
			return true
		}
	}
	return false
}

// awaitInvalidated waits for an id to be invalidated, and says what it did see
// when it is not. A revocation runs on the expiration manager's timer, so there
// is nothing to synchronise on but the effect itself.
func (s *elasticClusterStub) awaitInvalidated(t *testing.T, id string, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if s.sawInvalidated(id) {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("key %q was never invalidated within %s; the cluster was asked to invalidate %v",
		id, within, s.invalidatedKeys())
}

// elasticClusterKeyID reads the id half out of a pre-encoded cluster key, the
// way the cluster itself would.
func elasticClusterKeyID(encoded string) (string, bool) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", false
	}
	id, _, found := strings.Cut(string(raw), ":")
	if !found || id == "" {
		return "", false
	}
	return id, true
}

func startElasticClusterStub(t *testing.T) *elasticClusterStub {
	t.Helper()

	stub := &elasticClusterStub{}
	mux := http.NewServeMux()

	// The identity behind whichever key authenticated. The id is derived from the
	// presented key rather than fixed, for two reasons: it is what makes the
	// driver's api_key_id cross-check meaningful, and it is what lets this stub
	// keep answering correctly after a rotation has replaced the source's key.
	mux.HandleFunc("/_security/_authenticate", func(w http.ResponseWriter, r *http.Request) {
		clusterKey, ok := strings.CutPrefix(r.Header.Get("Authorization"), "ApiKey ")
		if !ok || clusterKey == "" {
			http.Error(w, "missing ApiKey credential", http.StatusUnauthorized)
			return
		}
		id, ok := elasticClusterKeyID(clusterKey)
		if !ok {
			http.Error(w, "credential is not a pre-encoded api key", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"username": "warden-e2e",
			"enabled":  true,
			"api_key":  map[string]interface{}{"id": id, "name": "warden-source"},
		})
	})

	mux.HandleFunc("/_security/api_key", func(w http.ResponseWriter, r *http.Request) {
		clusterKey, ok := strings.CutPrefix(r.Header.Get("Authorization"), "ApiKey ")
		if !ok || clusterKey == "" {
			http.Error(w, "missing ApiKey credential", http.StatusUnauthorized)
			return
		}

		var body map[string]interface{}
		if r.Body != nil {
			_ = json.NewDecoder(r.Body).Decode(&body)
		}

		switch r.Method {
		case http.MethodPost:
			metadata, _ := body["metadata"].(map[string]interface{})
			purpose, _ := metadata["purpose"].(string)

			if purpose == "source_rotation" {
				// A rotation key gets an id of its own, so a row asserting that the
				// OLD key was invalidated is asserting something.
				stub.mu.Lock()
				stub.rotations++
				id := fmt.Sprintf("%s%d", elasticRotatedKeyPrefix, stub.rotations)
				stub.mu.Unlock()

				stub.recordCreate(elasticCreate{ClusterKey: clusterKey, Body: body, MintedID: id})
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"id":      id,
					"name":    body["name"],
					"encoded": base64.StdEncoding.EncodeToString([]byte(id + ":rotated-secret")),
				})
				return
			}

			// A key created without an expiration never expires, and a chained mint
			// is never revoked — so refuse one here too. A cluster that accepted it
			// would let that regression pass as a green row.
			if exp, _ := body["expiration"].(string); exp == "" {
				http.Error(w, "refusing to create a key with no expiration", http.StatusBadRequest)
				return
			}

			stub.recordCreate(elasticCreate{ClusterKey: clusterKey, Body: body, MintedID: elasticMintedKeyID})
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"id":         elasticMintedKeyID,
				"name":       body["name"],
				"encoded":    elasticMintedFor(clusterKey),
				"expiration": time.Now().Add(time.Hour).UnixMilli(),
			})

		case http.MethodDelete:
			ids, _ := body["ids"].([]interface{})
			invalidated := make([]string, 0, len(ids))
			for _, id := range ids {
				if s, ok := id.(string); ok {
					invalidated = append(invalidated, s)
				}
			}
			stub.mu.Lock()
			stub.invalidated = append(stub.invalidated, invalidated...)
			stub.batches = append(stub.batches, invalidated)
			// An invalidated key is no longer sweepable, which is what stops a
			// second rotation from reclaiming the same one twice.
			remaining := stub.queryable[:0:0]
			for _, q := range stub.queryable {
				gone := false
				for _, done := range invalidated {
					if q == done {
						gone = true
					}
				}
				if !gone {
					remaining = append(remaining, q)
				}
			}
			stub.queryable = remaining
			stub.mu.Unlock()

			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"invalidated_api_keys":            invalidated,
				"previously_invalidated_api_keys": []string{},
				"error_count":                     0,
			})

		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	// The listing the rotation orphan sweep runs. Reports only what a row primed,
	// so a suite that does not care about the sweep sees an empty cluster.
	mux.HandleFunc("/_security/_query/api_key", func(w http.ResponseWriter, _ *http.Request) {
		stub.mu.Lock()
		found := make([]interface{}, 0, len(stub.queryable))
		for _, id := range stub.queryable {
			found = append(found, map[string]interface{}{"id": id, "name": "warden-source-rotated"})
		}
		stub.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"api_keys": found})
	})

	stub.Server = httptest.NewServer(mux)
	t.Cleanup(stub.Close)
	return stub
}
