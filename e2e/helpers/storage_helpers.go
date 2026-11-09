//go:build e2e

package helpers

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hashicorp/go-hclog"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
	statickms "github.com/openbao/go-kms-wrapping/wrappers/static/v2"
	"github.com/openbao/openbao/sdk/v2/helper/jsonutil"
	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"google.golang.org/protobuf/proto"

	"github.com/stephnangue/warden/core"
	"github.com/stephnangue/warden/core/seal"
	"github.com/stephnangue/warden/physical/postgresql"
)

// --- The cluster's storage, written from outside ---
//
// Some states the suites must reach can no longer be produced through the API:
// data an earlier release wrote, which this one only reads. ClusterStorage opens
// the cluster's storage the way a node does, unsealed with the configured seal,
// so a test can put such an entry where the earlier release put it, encrypted
// exactly as a node would read it. Nodes read storage at unseal; a test seeds,
// then restarts the nodes it wants to see the entry.

const (
	// e2eStorageURL and e2eStorageTable are the storage stanza of the node
	// configs (e2e/configs/node*.hcl).
	e2eStorageURL   = "postgres://warden:wardenpassword@localhost:5433/warden?sslmode=disable"
	e2eStorageTable = "e2e_kv_store"
	// e2eSealKeyID is the static seal's current_key_id in the node configs.
	e2eSealKeyID = "20251221-1"
	// storedBarrierKeysPath is where the seal keeps the barrier's root key.
	storedBarrierKeysPath = "core/hsm/barrier-unseal-keys"
)

// ClusterStorage is the cluster's storage behind its barrier.
type ClusterStorage struct {
	barrier core.SecurityBarrier
}

// OpenClusterStorage unseals a barrier over the cluster's storage with the
// static seal key every node uses. It is sealed again when the test ends.
func OpenClusterStorage(t *testing.T) *ClusterStorage {
	t.Helper()
	ctx := context.Background()

	backend, err := postgresql.NewPostgreSQLBackend(map[string]string{
		"connection_url": e2eStorageURL,
		"table":          e2eStorageTable,
	}, hclog.NewNullLogger())
	if err != nil {
		t.Fatalf("open the cluster's storage: %v", err)
	}

	wrapper := statickms.NewWrapper()
	if _, err := wrapper.SetConfig(ctx, wrapping.WithConfigMap(map[string]string{
		"current_key_id": e2eSealKeyID,
		"current_key":    "file://" + filepath.Join(E2EDir(), "configs", "seal.key"),
	})); err != nil {
		t.Fatalf("configure the static seal: %v", err)
	}
	access := seal.NewAccess(wrapper)

	pe, err := backend.Get(ctx, storedBarrierKeysPath)
	if err != nil || pe == nil {
		t.Fatalf("read the stored barrier keys (entry %v): %v", pe != nil, err)
	}
	blob := &wrapping.BlobInfo{}
	if err := proto.Unmarshal(pe.Value, blob); err != nil {
		t.Fatalf("decode the stored barrier keys: %v", err)
	}
	pt, err := access.Decrypt(ctx, blob, nil)
	if err != nil {
		t.Fatalf("decrypt the stored barrier keys with the seal: %v", err)
	}
	var keys [][]byte
	if err := json.Unmarshal(pt, &keys); err != nil || len(keys) == 0 {
		t.Fatalf("decode the barrier root key (%d keys): %v", len(keys), err)
	}

	barrier, err := core.NewAESGCMBarrier(backend)
	if err != nil {
		t.Fatalf("build the barrier: %v", err)
	}
	if err := barrier.Unseal(ctx, keys[0]); err != nil {
		t.Fatalf("unseal the barrier: %v", err)
	}
	t.Cleanup(func() { _ = barrier.Seal() })
	return &ClusterStorage{barrier: barrier}
}

// Put writes value at key, as a node writes it.
func (s *ClusterStorage) Put(t *testing.T, key string, value []byte) {
	t.Helper()
	if err := s.barrier.Put(context.Background(), &sdklogical.StorageEntry{Key: key, Value: value}); err != nil {
		t.Fatalf("write %s: %v", key, err)
	}
}

// PutJSON writes v, JSON-encoded, at key.
func (s *ClusterStorage) PutJSON(t *testing.T, key string, v any) {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal %s: %v", key, err)
	}
	s.Put(t, key, b)
}

// Get returns the value at key, nil when there is none.
func (s *ClusterStorage) Get(t *testing.T, key string) []byte {
	t.Helper()
	e, err := s.barrier.Get(context.Background(), key)
	if err != nil {
		t.Fatalf("read %s: %v", key, err)
	}
	if e == nil {
		return nil
	}
	return e.Value
}

// List returns the keys directly under prefix.
func (s *ClusterStorage) List(t *testing.T, prefix string) []string {
	t.Helper()
	keys, err := s.barrier.List(context.Background(), prefix)
	if err != nil {
		t.Fatalf("list %s: %v", prefix, err)
	}
	return keys
}

// Delete removes key.
func (s *ClusterStorage) Delete(t *testing.T, key string) {
	t.Helper()
	if err := s.barrier.Delete(context.Background(), key); err != nil {
		t.Fatalf("delete %s: %v", key, err)
	}
}

// AuthMountUUID returns the UUID of the root namespace's auth mount at path
// ("auth/jwt/", "jwt" or "jwt/"): the name of its storage, which the API does
// not show.
func (s *ClusterStorage) AuthMountUUID(t *testing.T, path string) string {
	t.Helper()
	return s.mountUUID(t, "core/auth/", strings.TrimPrefix(AuthMountPath(path), "auth/"))
}

// ProviderMountUUID returns the UUID of the root namespace's provider mount at
// path ("vault" or "vault/").
func (s *ClusterStorage) ProviderMountUUID(t *testing.T, path string) string {
	t.Helper()
	return s.mountUUID(t, "core/mounts/", strings.Trim(path, "/")+"/")
}

// AuthMountStorage is the storage prefix of the root namespace's auth mount
// with UUID uuid.
func AuthMountStorage(uuid string) string { return "auth/" + uuid + "/" }

// ProviderMountStorage is the storage prefix of the root namespace's provider
// mount with UUID uuid.
func ProviderMountStorage(uuid string) string { return "provider/" + uuid + "/" }

func (s *ClusterStorage) mountUUID(t *testing.T, table, path string) string {
	t.Helper()
	ctx := context.Background()
	ids, err := s.barrier.List(ctx, table)
	if err != nil {
		t.Fatalf("list %s: %v", table, err)
	}
	for _, id := range ids {
		e, err := s.barrier.Get(ctx, table+id)
		if err != nil || e == nil {
			continue
		}
		var entry struct {
			Path string `json:"path"`
			UUID string `json:"uuid"`
		}
		if err := jsonutil.DecodeJSON(e.Value, &entry); err != nil {
			continue
		}
		if entry.Path == path {
			if entry.UUID == "" {
				return id
			}
			return entry.UUID
		}
	}
	t.Fatalf("no mount at %q in %s", path, table)
	return ""
}
