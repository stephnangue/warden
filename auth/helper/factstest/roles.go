package factstest

import (
	"context"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"

	"github.com/stephnangue/warden/auth/helper"
	"github.com/stephnangue/warden/logical"
)

// RecordingStorage wraps a storage and counts every operation on a key under
// helper.RolePrefix, so a test can show the old auth role storage is never
// touched.
type RecordingStorage struct {
	sdklogical.Storage
	roleOps atomic.Int64
}

func (s *RecordingStorage) note(key string) {
	if strings.HasPrefix(key, helper.RolePrefix) {
		s.roleOps.Add(1)
	}
}

// RoleOps returns how many operations touched a key under helper.RolePrefix.
func (s *RecordingStorage) RoleOps() int64 { return s.roleOps.Load() }

func (s *RecordingStorage) List(ctx context.Context, prefix string) ([]string, error) {
	s.note(prefix)
	return s.Storage.List(ctx, prefix)
}

func (s *RecordingStorage) Get(ctx context.Context, key string) (*sdklogical.StorageEntry, error) {
	s.note(key)
	return s.Storage.Get(ctx, key)
}

func (s *RecordingStorage) Put(ctx context.Context, entry *sdklogical.StorageEntry) error {
	s.note(entry.Key)
	return s.Storage.Put(ctx, entry)
}

func (s *RecordingStorage) Delete(ctx context.Context, key string) error {
	s.note(key)
	return s.Storage.Delete(ctx, key)
}

// AssertRolesGone sends every operation to role/, role/<name> and a nested
// path under role/ on b and asserts each answers 410 Gone with
// helper.AuthRolesRemovedMessage.
func AssertRolesGone(t testing.TB, b logical.Backend) {
	t.Helper()
	ops := []logical.Operation{
		logical.CreateOperation, logical.ReadOperation, logical.UpdateOperation,
		logical.PatchOperation, logical.DeleteOperation, logical.ListOperation,
	}
	for _, path := range []string{"role/", "role", "role/deploy", "role/a/b"} {
		for _, op := range ops {
			resp, err := b.HandleRequest(context.Background(), &logical.Request{
				Operation: op,
				Path:      path,
				Data:      map[string]any{"token_policies": "admin"},
			})
			if err != nil {
				t.Errorf("%s %s: %v", op, path, err)
				continue
			}
			if resp == nil || resp.StatusCode != http.StatusGone || resp.Err == nil ||
				resp.Err.Error() != helper.AuthRolesRemovedMessage {
				t.Errorf("%s %s: want 410 %q, got %+v", op, path, helper.AuthRolesRemovedMessage, resp)
			}
		}
	}
}
