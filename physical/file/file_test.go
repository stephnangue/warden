package file

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/physical"
)

func TestFileBackend_NewFileBackend(t *testing.T) {
	t.Run("successful creation", func(t *testing.T) {
		tmpDir := t.TempDir()
		conf := map[string]string{
			"path": tmpDir,
		}

		testLogger := logger.NewZerologLogger(logger.DefaultConfig())
		backend, err := NewFileBackend(conf, testLogger)

		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if backend == nil {
			t.Fatal("expected backend to be non-nil")
		}
	})

	t.Run("missing path configuration", func(t *testing.T) {
		conf := map[string]string{}
		testLogger := logger.NewZerologLogger(logger.DefaultConfig())

		_, err := NewFileBackend(conf, testLogger)

		if err == nil {
			t.Fatal("expected error for missing path, got nil")
		}
		if err.Error() != "'path' must be set" {
			t.Fatalf("expected error message \"'path' must be set\", got %v", err)
		}
	})
}

func TestFileBackend_Put_Get_Delete(t *testing.T) {
	tmpDir := t.TempDir()
	backend := setupBackend(t, tmpDir)
	ctx := context.Background()

	entry := &physical.Entry{
		Key:   "test/key",
		Value: []byte("test value"),
	}

	// Test Put
	err := backend.Put(ctx, entry)
	if err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	// Test Get
	retrieved, err := backend.Get(ctx, "test/key")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if retrieved == nil {
		t.Fatal("expected entry to be retrieved, got nil")
	}
	if retrieved.Key != entry.Key {
		t.Fatalf("expected key %q, got %q", entry.Key, retrieved.Key)
	}
	if !reflect.DeepEqual(retrieved.Value, entry.Value) {
		t.Fatalf("expected value %v, got %v", entry.Value, retrieved.Value)
	}

	// Test Delete
	err = backend.Delete(ctx, "test/key")
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	// Verify deletion
	retrieved, err = backend.Get(ctx, "test/key")
	if err != nil {
		t.Fatalf("Get after delete failed: %v", err)
	}
	if retrieved != nil {
		t.Fatal("expected nil after delete, got entry")
	}
}

func TestFileBackend_Get_NonExistent(t *testing.T) {
	tmpDir := t.TempDir()
	backend := setupBackend(t, tmpDir)
	ctx := context.Background()

	retrieved, err := backend.Get(ctx, "nonexistent/key")
	if err != nil {
		t.Fatalf("expected no error for non-existent key, got %v", err)
	}
	if retrieved != nil {
		t.Fatal("expected nil for non-existent key, got entry")
	}
}

func TestFileBackend_Delete_NonExistent(t *testing.T) {
	tmpDir := t.TempDir()
	backend := setupBackend(t, tmpDir)
	ctx := context.Background()

	err := backend.Delete(ctx, "nonexistent/key")
	if err != nil {
		t.Fatalf("expected no error for deleting non-existent key, got %v", err)
	}
}

func TestFileBackend_Delete_EmptyPath(t *testing.T) {
	tmpDir := t.TempDir()
	backend := setupBackend(t, tmpDir)
	ctx := context.Background()

	err := backend.Delete(ctx, "")
	if err != nil {
		t.Fatalf("expected no error for empty path, got %v", err)
	}
}

func TestFileBackend_List(t *testing.T) {
	tmpDir := t.TempDir()
	backend := setupBackend(t, tmpDir)
	ctx := context.Background()

	// Create test entries
	entries := []*physical.Entry{
		{Key: "test/key1", Value: []byte("value1")},
		{Key: "test/key2", Value: []byte("value2")},
		{Key: "test/subdir/key3", Value: []byte("value3")},
		{Key: "other/key4", Value: []byte("value4")},
	}

	for _, entry := range entries {
		if err := backend.Put(ctx, entry); err != nil {
			t.Fatalf("Put failed: %v", err)
		}
	}

	// List with prefix "test/"
	keys, err := backend.List(ctx, "test/")
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}

	expected := []string{"key1", "key2", "subdir/"}
	if !reflect.DeepEqual(keys, expected) {
		t.Fatalf("expected keys %v, got %v", expected, keys)
	}
}

func TestFileBackend_List_Empty(t *testing.T) {
	tmpDir := t.TempDir()
	backend := setupBackend(t, tmpDir)
	ctx := context.Background()

	keys, err := backend.List(ctx, "nonexistent/")
	if err != nil {
		t.Fatalf("expected no error for non-existent prefix, got %v", err)
	}
	if keys != nil {
		t.Fatalf("expected nil for non-existent prefix, got %v", keys)
	}
}

func TestFileBackend_List_RootPrefix(t *testing.T) {
	tmpDir := t.TempDir()
	backend := setupBackend(t, tmpDir)
	ctx := context.Background()

	// Create test entries
	entries := []*physical.Entry{
		{Key: "key1", Value: []byte("value1")},
		{Key: "key2", Value: []byte("value2")},
		{Key: "dir/key3", Value: []byte("value3")},
	}

	for _, entry := range entries {
		if err := backend.Put(ctx, entry); err != nil {
			t.Fatalf("Put failed: %v", err)
		}
	}

	// List with empty prefix
	keys, err := backend.List(ctx, "")
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}

	expected := []string{"dir/", "key1", "key2"}
	if !reflect.DeepEqual(keys, expected) {
		t.Fatalf("expected keys %v, got %v", expected, keys)
	}
}

func TestFileBackend_ValidatePath(t *testing.T) {
	tmpDir := t.TempDir()
	backend := setupBackend(t, tmpDir)

	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{
			name:    "valid path",
			path:    "test/key",
			wantErr: false,
		},
		{
			name:    "parent reference",
			path:    "../test",
			wantErr: true,
		},
		{
			name:    "parent reference in middle",
			path:    "test/../key",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := backend.(*FileBackend).validatePath(tt.path)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validatePath() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr && err != physical.ErrPathContainsParentReferences {
				t.Fatalf("expected ErrPathContainsParentReferences, got %v", err)
			}
		})
	}
}

func TestFileBackend_Put_InvalidPath(t *testing.T) {
	tmpDir := t.TempDir()
	backend := setupBackend(t, tmpDir)
	ctx := context.Background()

	entry := &physical.Entry{
		Key:   "../invalid",
		Value: []byte("value"),
	}

	err := backend.Put(ctx, entry)
	if err == nil {
		t.Fatal("expected error for invalid path, got nil")
	}
	if err != physical.ErrPathContainsParentReferences {
		t.Fatalf("expected ErrPathContainsParentReferences, got %v", err)
	}
}

func TestFileBackend_Get_InvalidPath(t *testing.T) {
	tmpDir := t.TempDir()
	backend := setupBackend(t, tmpDir)
	ctx := context.Background()

	_, err := backend.Get(ctx, "../invalid")
	if err == nil {
		t.Fatal("expected error for invalid path, got nil")
	}
	if err != physical.ErrPathContainsParentReferences {
		t.Fatalf("expected ErrPathContainsParentReferences, got %v", err)
	}
}

func TestFileBackend_Delete_InvalidPath(t *testing.T) {
	tmpDir := t.TempDir()
	backend := setupBackend(t, tmpDir)
	ctx := context.Background()

	err := backend.Delete(ctx, "../invalid")
	if err == nil {
		t.Fatal("expected error for invalid path, got nil")
	}
	if err != physical.ErrPathContainsParentReferences {
		t.Fatalf("expected ErrPathContainsParentReferences, got %v", err)
	}
}

func TestFileBackend_List_InvalidPath(t *testing.T) {
	tmpDir := t.TempDir()
	backend := setupBackend(t, tmpDir)
	ctx := context.Background()

	_, err := backend.List(ctx, "../invalid")
	if err == nil {
		t.Fatal("expected error for invalid path, got nil")
	}
	if err != physical.ErrPathContainsParentReferences {
		t.Fatalf("expected ErrPathContainsParentReferences, got %v", err)
	}
}

func TestFileBackend_ContextCancellation(t *testing.T) {
	tmpDir := t.TempDir()
	backend := setupBackend(t, tmpDir)

	t.Run("Put with cancelled context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		entry := &physical.Entry{
			Key:   "test/key",
			Value: []byte("value"),
		}

		err := backend.Put(ctx, entry)
		if err == nil {
			t.Fatal("expected error for cancelled context")
		}
	})

	t.Run("Get with cancelled context", func(t *testing.T) {
		// First put an entry
		ctx := context.Background()
		entry := &physical.Entry{
			Key:   "test/key",
			Value: []byte("value"),
		}
		backend.Put(ctx, entry)

		// Now try to get with cancelled context
		cancelledCtx, cancel := context.WithCancel(context.Background())
		cancel()

		_, err := backend.Get(cancelledCtx, "test/key")
		if err == nil {
			t.Fatal("expected error for cancelled context")
		}
	})

	t.Run("List with cancelled context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())

		// Put some entries first
		entry := &physical.Entry{
			Key:   "test/key",
			Value: []byte("value"),
		}
		backend.Put(context.Background(), entry)

		cancel()

		_, err := backend.List(ctx, "test/")
		if err == nil {
			t.Fatal("expected error for cancelled context")
		}
	})
}

func TestFileBackend_CleanupLogicalPath(t *testing.T) {
	tmpDir := t.TempDir()
	backend := setupBackend(t, tmpDir)
	ctx := context.Background()

	// Create nested entries
	entry1 := &physical.Entry{
		Key:   "level1/level2/level3/key1",
		Value: []byte("value1"),
	}
	entry2 := &physical.Entry{
		Key:   "level1/level2/key2",
		Value: []byte("value2"),
	}

	backend.Put(ctx, entry1)
	backend.Put(ctx, entry2)

	// Delete the deepest entry
	backend.Delete(ctx, "level1/level2/level3/key1")

	// Verify that level3 directory was cleaned up
	level3Path := filepath.Join(tmpDir, "level1", "level2", "level3")
	if _, err := os.Stat(level3Path); !os.IsNotExist(err) {
		t.Fatal("expected level3 directory to be cleaned up")
	}

	// Verify that level2 still exists (it has key2)
	level2Path := filepath.Join(tmpDir, "level1", "level2")
	if _, err := os.Stat(level2Path); err != nil {
		t.Fatalf("expected level2 directory to exist: %v", err)
	}

	// Delete the remaining entry
	backend.Delete(ctx, "level1/level2/key2")

	// Verify that level2 and level1 were cleaned up
	if _, err := os.Stat(level2Path); !os.IsNotExist(err) {
		t.Fatal("expected level2 directory to be cleaned up")
	}
}

func TestFileBackend_ExpandPath(t *testing.T) {
	tmpDir := t.TempDir()
	backend := setupBackend(t, tmpDir).(*FileBackend)

	tests := []struct {
		name         string
		key          string
		expectedPath string
		expectedKey  string
	}{
		{
			name:         "simple key",
			key:          "key",
			expectedPath: tmpDir,
			expectedKey:  "_key",
		},
		{
			name:         "nested key",
			key:          "level1/level2/key",
			expectedPath: filepath.Join(tmpDir, "level1", "level2"),
			expectedKey:  "_key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path, key := backend.expandPath(tt.key)
			if path != tt.expectedPath {
				t.Fatalf("expected path %q, got %q", tt.expectedPath, path)
			}
			if key != tt.expectedKey {
				t.Fatalf("expected key %q, got %q", tt.expectedKey, key)
			}
		})
	}
}

func TestFileBackend_ZeroLengthFile(t *testing.T) {
	tmpDir := t.TempDir()
	backend := setupBackend(t, tmpDir).(*FileBackend)
	ctx := context.Background()

	// Create a zero-length file manually
	path, key := backend.expandPath("test/key")
	os.MkdirAll(path, 0o700)
	fullPath := filepath.Join(path, key)
	f, err := os.Create(fullPath)
	if err != nil {
		t.Fatalf("failed to create zero-length file: %v", err)
	}
	f.Close()

	// Try to get it - should return nil and remove the file
	entry, err := backend.Get(ctx, "test/key")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if entry != nil {
		t.Fatal("expected nil for zero-length file")
	}

	// Verify file was removed
	if _, err := os.Stat(fullPath); !os.IsNotExist(err) {
		t.Fatal("expected zero-length file to be removed")
	}
}

func TestFileBackend_ListPage(t *testing.T) {
	tmpDir := t.TempDir()
	backend := setupBackend(t, tmpDir).(*FileBackend)
	ctx := context.Background()

	// Create test entries with predictable names
	keys := []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j"}
	for _, key := range keys {
		entry := &physical.Entry{
			Key:   "test/" + key,
			Value: []byte("value"),
		}
		if err := backend.Put(ctx, entry); err != nil {
			t.Fatalf("Put failed: %v", err)
		}
	}

	t.Run("first page with limit", func(t *testing.T) {
		result, err := backend.ListPageInternal(ctx, "test/", "", 5)
		if err != nil {
			t.Fatalf("ListPageInternal failed: %v", err)
		}
		if len(result) != 5 {
			t.Fatalf("expected 5 keys, got %d", len(result))
		}
		expected := []string{"a", "b", "c", "d", "e"}
		if !reflect.DeepEqual(result, expected) {
			t.Fatalf("expected %v, got %v", expected, result)
		}
	})

	t.Run("second page with after", func(t *testing.T) {
		result, err := backend.ListPageInternal(ctx, "test/", "e", 5)
		if err != nil {
			t.Fatalf("ListPageInternal failed: %v", err)
		}
		if len(result) != 5 {
			t.Fatalf("expected 5 keys, got %d", len(result))
		}
		expected := []string{"f", "g", "h", "i", "j"}
		if !reflect.DeepEqual(result, expected) {
			t.Fatalf("expected %v, got %v", expected, result)
		}
	})

	t.Run("last page partial results", func(t *testing.T) {
		result, err := backend.ListPageInternal(ctx, "test/", "h", 5)
		if err != nil {
			t.Fatalf("ListPageInternal failed: %v", err)
		}
		if len(result) != 2 {
			t.Fatalf("expected 2 keys, got %d", len(result))
		}
		expected := []string{"i", "j"}
		if !reflect.DeepEqual(result, expected) {
			t.Fatalf("expected %v, got %v", expected, result)
		}
	})

	t.Run("no limit returns all", func(t *testing.T) {
		result, err := backend.ListPageInternal(ctx, "test/", "", -1)
		if err != nil {
			t.Fatalf("ListPageInternal failed: %v", err)
		}
		if len(result) != 10 {
			t.Fatalf("expected 10 keys, got %d", len(result))
		}
	})

	t.Run("limit larger than results", func(t *testing.T) {
		result, err := backend.ListPageInternal(ctx, "test/", "", 100)
		if err != nil {
			t.Fatalf("ListPageInternal failed: %v", err)
		}
		if len(result) != 10 {
			t.Fatalf("expected 10 keys, got %d", len(result))
		}
	})

	t.Run("after non-existent key", func(t *testing.T) {
		// "aa" would come after "a" but before "b" in sorted order
		result, err := backend.ListPageInternal(ctx, "test/", "aa", 5)
		if err != nil {
			t.Fatalf("ListPageInternal failed: %v", err)
		}
		// Should return keys starting from "b"
		expected := []string{"b", "c", "d", "e", "f"}
		if !reflect.DeepEqual(result, expected) {
			t.Fatalf("expected %v, got %v", expected, result)
		}
	})

	t.Run("after last key", func(t *testing.T) {
		result, err := backend.ListPageInternal(ctx, "test/", "j", 5)
		if err != nil {
			t.Fatalf("ListPageInternal failed: %v", err)
		}
		if len(result) != 0 {
			t.Fatalf("expected 0 keys, got %d", len(result))
		}
	})
}

func TestFileBackend_ListPage_WithDirectories(t *testing.T) {
	tmpDir := t.TempDir()
	backend := setupBackend(t, tmpDir)
	ctx := context.Background()

	// Create mixed entries: files and directories
	entries := []*physical.Entry{
		{Key: "test/aaa", Value: []byte("value1")},
		{Key: "test/bbb", Value: []byte("value2")},
		{Key: "test/dir1/key1", Value: []byte("value3")},
		{Key: "test/dir2/key2", Value: []byte("value4")},
		{Key: "test/zzz", Value: []byte("value5")},
	}

	for _, entry := range entries {
		if err := backend.Put(ctx, entry); err != nil {
			t.Fatalf("Put failed: %v", err)
		}
	}

	t.Run("list with directories first page", func(t *testing.T) {
		result, err := backend.ListPage(ctx, "test/", "", 3)
		if err != nil {
			t.Fatalf("ListPage failed: %v", err)
		}
		// Should be sorted: aaa, bbb, dir1/, dir2/, zzz
		expected := []string{"aaa", "bbb", "dir1/"}
		if !reflect.DeepEqual(result, expected) {
			t.Fatalf("expected %v, got %v", expected, result)
		}
	})

	t.Run("list with directories second page", func(t *testing.T) {
		result, err := backend.ListPage(ctx, "test/", "dir1/", 3)
		if err != nil {
			t.Fatalf("ListPage failed: %v", err)
		}
		expected := []string{"dir2/", "zzz"}
		if !reflect.DeepEqual(result, expected) {
			t.Fatalf("expected %v, got %v", expected, result)
		}
	})
}

func TestFileBackend_ListPage_EmptyPrefix(t *testing.T) {
	tmpDir := t.TempDir()
	backend := setupBackend(t, tmpDir)
	ctx := context.Background()

	// Create entries at root level
	entries := []*physical.Entry{
		{Key: "key1", Value: []byte("value1")},
		{Key: "key2", Value: []byte("value2")},
		{Key: "key3", Value: []byte("value3")},
	}

	for _, entry := range entries {
		if err := backend.Put(ctx, entry); err != nil {
			t.Fatalf("Put failed: %v", err)
		}
	}

	result, err := backend.ListPage(ctx, "", "", 2)
	if err != nil {
		t.Fatalf("ListPage failed: %v", err)
	}
	if len(result) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(result))
	}
	expected := []string{"key1", "key2"}
	if !reflect.DeepEqual(result, expected) {
		t.Fatalf("expected %v, got %v", expected, result)
	}
}

func TestFileBackend_ListPage_NonExistentPrefix(t *testing.T) {
	tmpDir := t.TempDir()
	backend := setupBackend(t, tmpDir)
	ctx := context.Background()

	result, err := backend.ListPage(ctx, "nonexistent/", "", 10)
	if err != nil {
		t.Fatalf("expected no error for non-existent prefix, got %v", err)
	}
	if result != nil {
		t.Fatalf("expected nil for non-existent prefix, got %v", result)
	}
}

func TestFileBackend_ListPage_InvalidPath(t *testing.T) {
	tmpDir := t.TempDir()
	backend := setupBackend(t, tmpDir)
	ctx := context.Background()

	_, err := backend.ListPage(ctx, "../invalid", "", 10)
	if err == nil {
		t.Fatal("expected error for invalid path, got nil")
	}
	if err != physical.ErrPathContainsParentReferences {
		t.Fatalf("expected ErrPathContainsParentReferences, got %v", err)
	}
}

func TestFileBackend_ListPage_CancelledContext(t *testing.T) {
	tmpDir := t.TempDir()
	backend := setupBackend(t, tmpDir)

	// Create some test entries
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		entry := &physical.Entry{
			Key:   fmt.Sprintf("test/key%d", i),
			Value: []byte("value"),
		}
		backend.Put(ctx, entry)
	}

	// Try to list with cancelled context
	cancelledCtx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := backend.ListPage(cancelledCtx, "test/", "", 10)
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}
}

func TestFileBackend_ListSorting(t *testing.T) {
	tmpDir := t.TempDir()
	backend := setupBackend(t, tmpDir)
	ctx := context.Background()

	// Create entries in non-alphabetical order
	entries := []*physical.Entry{
		{Key: "test/zebra", Value: []byte("value")},
		{Key: "test/alpha", Value: []byte("value")},
		{Key: "test/beta", Value: []byte("value")},
	}

	for _, entry := range entries {
		backend.Put(ctx, entry)
	}

	keys, err := backend.List(ctx, "test/")
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}

	expected := []string{"alpha", "beta", "zebra"}
	if !reflect.DeepEqual(keys, expected) {
		t.Fatalf("expected sorted keys %v, got %v", expected, keys)
	}
}

func TestFileBackend_ConcurrentOperations(t *testing.T) {
	tmpDir := t.TempDir()
	backend := setupBackend(t, tmpDir)
	ctx := context.Background()

	const numGoroutines = 10
	done := make(chan bool, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer func() { done <- true }()

			key := filepath.Join("concurrent", filepath.Base(filepath.Join("", string(rune('0'+id)))))
			entry := &physical.Entry{
				Key:   key,
				Value: []byte("value"),
			}

			// Put
			if err := backend.Put(ctx, entry); err != nil {
				t.Errorf("Put failed: %v", err)
				return
			}

			// Get
			if _, err := backend.Get(ctx, key); err != nil {
				t.Errorf("Get failed: %v", err)
				return
			}

			// Delete
			if err := backend.Delete(ctx, key); err != nil {
				t.Errorf("Delete failed: %v", err)
			}
		}(i)
	}

	for i := 0; i < numGoroutines; i++ {
		<-done
	}
}

func TestFileBackend_UpdateExistingKey(t *testing.T) {
	tmpDir := t.TempDir()
	backend := setupBackend(t, tmpDir)
	ctx := context.Background()

	key := "test/key"

	// Put initial value
	entry1 := &physical.Entry{
		Key:   key,
		Value: []byte("initial value"),
	}
	err := backend.Put(ctx, entry1)
	if err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	// Update with new value
	entry2 := &physical.Entry{
		Key:   key,
		Value: []byte("updated value"),
	}
	err = backend.Put(ctx, entry2)
	if err != nil {
		t.Fatalf("Put update failed: %v", err)
	}

	// Verify updated value
	retrieved, err := backend.Get(ctx, key)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if !reflect.DeepEqual(retrieved.Value, entry2.Value) {
		t.Fatalf("expected value %v, got %v", entry2.Value, retrieved.Value)
	}
}

func TestFileBackend_PutLargeValue(t *testing.T) {
	tmpDir := t.TempDir()
	backend := setupBackend(t, tmpDir)
	ctx := context.Background()

	// Create a large value (1MB)
	largeValue := make([]byte, 1024*1024)
	for i := range largeValue {
		largeValue[i] = byte(i % 256)
	}

	entry := &physical.Entry{
		Key:   "test/large",
		Value: largeValue,
	}

	err := backend.Put(ctx, entry)
	if err != nil {
		t.Fatalf("Put large value failed: %v", err)
	}

	retrieved, err := backend.Get(ctx, "test/large")
	if err != nil {
		t.Fatalf("Get large value failed: %v", err)
	}
	if !reflect.DeepEqual(retrieved.Value, largeValue) {
		t.Fatal("large value mismatch")
	}
}

func TestFileBackend_DeepNestedPaths(t *testing.T) {
	tmpDir := t.TempDir()
	backend := setupBackend(t, tmpDir)
	ctx := context.Background()

	// Create deeply nested path
	deepPath := "level1/level2/level3/level4/level5/key"
	entry := &physical.Entry{
		Key:   deepPath,
		Value: []byte("deep value"),
	}

	err := backend.Put(ctx, entry)
	if err != nil {
		t.Fatalf("Put deep path failed: %v", err)
	}

	retrieved, err := backend.Get(ctx, deepPath)
	if err != nil {
		t.Fatalf("Get deep path failed: %v", err)
	}
	if retrieved == nil {
		t.Fatal("expected entry, got nil")
	}

	// List at various levels
	keys, err := backend.List(ctx, "level1/")
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(keys) != 1 || keys[0] != "level2/" {
		t.Fatalf("expected [level2/], got %v", keys)
	}
}

func TestFileBackend_EmptyValue(t *testing.T) {
	tmpDir := t.TempDir()
	backend := setupBackend(t, tmpDir)
	ctx := context.Background()

	entry := &physical.Entry{
		Key:   "test/empty",
		Value: []byte{},
	}

	err := backend.Put(ctx, entry)
	if err != nil {
		t.Fatalf("Put empty value failed: %v", err)
	}

	retrieved, err := backend.Get(ctx, "test/empty")
	if err != nil {
		t.Fatalf("Get empty value failed: %v", err)
	}
	if retrieved == nil {
		t.Fatal("expected entry, got nil")
	}
	if len(retrieved.Value) != 0 {
		t.Fatalf("expected empty value, got %d bytes", len(retrieved.Value))
	}
}

// Helper function to set up a backend for testing
func setupBackend(t *testing.T, path string) physical.Storage {
	t.Helper()

	conf := map[string]string{
		"path": path,
	}
	testLogger := logger.NewZerologLogger(logger.DefaultConfig())

	backend, err := NewFileBackend(conf, testLogger)
	if err != nil {
		t.Fatalf("failed to create backend: %v", err)
	}

	return backend
}
