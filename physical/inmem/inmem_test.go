package inmem

import (
	"context"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/physical"
)

func TestInmemStorage_Basic(t *testing.T) {
	logger := logger.NewZerologLogger(logger.DefaultConfig())
	storage, err := NewInmem(nil, logger)
	if err != nil {
		t.Fatalf("failed to create inmem storage: %v", err)
	}

	ctx := context.Background()

	// Test Put
	entry := &physical.Entry{
		Key:   "test/key",
		Value: []byte("test value"),
	}
	if err := storage.Put(ctx, entry); err != nil {
		t.Fatalf("failed to put entry: %v", err)
	}

	// Test Get
	result, err := storage.Get(ctx, "test/key")
	if err != nil {
		t.Fatalf("failed to get entry: %v", err)
	}
	if result == nil {
		t.Fatal("expected entry, got nil")
	}
	if result.Key != entry.Key {
		t.Errorf("expected key %s, got %s", entry.Key, result.Key)
	}
	if !reflect.DeepEqual(result.Value, entry.Value) {
		t.Errorf("expected value %v, got %v", entry.Value, result.Value)
	}

	// Test Update
	updatedEntry := &physical.Entry{
		Key:   "test/key",
		Value: []byte("updated value"),
	}
	if err := storage.Put(ctx, updatedEntry); err != nil {
		t.Fatalf("failed to update entry: %v", err)
	}

	result, err = storage.Get(ctx, "test/key")
	if err != nil {
		t.Fatalf("failed to get updated entry: %v", err)
	}
	if !reflect.DeepEqual(result.Value, updatedEntry.Value) {
		t.Errorf("expected updated value %v, got %v", updatedEntry.Value, result.Value)
	}

	// Test Delete
	if err := storage.Delete(ctx, "test/key"); err != nil {
		t.Fatalf("failed to delete entry: %v", err)
	}

	result, err = storage.Get(ctx, "test/key")
	if err != nil {
		t.Fatalf("failed to get deleted entry: %v", err)
	}
	if result != nil {
		t.Errorf("expected nil for deleted entry, got %v", result)
	}
}

func TestInmemStorage_List(t *testing.T) {
	logger := logger.NewZerologLogger(logger.DefaultConfig())
	storage, err := NewInmem(nil, logger)
	if err != nil {
		t.Fatalf("failed to create inmem storage: %v", err)
	}

	ctx := context.Background()

	// Create test entries
	entries := []struct {
		key   string
		value string
	}{
		{"test/a", "value a"},
		{"test/b", "value b"},
		{"test/c/d", "value d"},
		{"test/c/e", "value e"},
		{"other/f", "value f"},
	}

	for _, entry := range entries {
		if err := storage.Put(ctx, &physical.Entry{
			Key:   entry.key,
			Value: []byte(entry.value),
		}); err != nil {
			t.Fatalf("failed to put entry %s: %v", entry.key, err)
		}
	}

	// Test List with prefix
	list, err := storage.List(ctx, "test/")
	if err != nil {
		t.Fatalf("failed to list entries: %v", err)
	}

	expected := []string{"a", "b", "c/"}
	if !reflect.DeepEqual(list, expected) {
		t.Errorf("expected list %v, got %v", expected, list)
	}

	// Test List with nested prefix
	list, err = storage.List(ctx, "test/c/")
	if err != nil {
		t.Fatalf("failed to list nested entries: %v", err)
	}

	expected = []string{"d", "e"}
	if !reflect.DeepEqual(list, expected) {
		t.Errorf("expected nested list %v, got %v", expected, list)
	}

	// Test List with empty prefix
	list, err = storage.List(ctx, "")
	if err != nil {
		t.Fatalf("failed to list all entries: %v", err)
	}

	expected = []string{"other/", "test/"}
	if !reflect.DeepEqual(list, expected) {
		t.Errorf("expected full list %v, got %v", expected, list)
	}
}

func TestInmemStorage_ContextCancellation(t *testing.T) {
	logger := logger.NewZerologLogger(logger.DefaultConfig())
	storage, err := NewInmem(nil, logger)
	if err != nil {
		t.Fatalf("failed to create inmem storage: %v", err)
	}

	// Create a cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	entry := &physical.Entry{
		Key:   "test/key",
		Value: []byte("test value"),
	}

	// Test Put with cancelled context
	err = storage.Put(ctx, entry)
	if err != context.Canceled {
		t.Errorf("expected context.Canceled, got %v", err)
	}

	// Test Get with cancelled context
	_, err = storage.Get(ctx, "test/key")
	if err != context.Canceled {
		t.Errorf("expected context.Canceled, got %v", err)
	}

	// Test Delete with cancelled context
	err = storage.Delete(ctx, "test/key")
	if err != context.Canceled {
		t.Errorf("expected context.Canceled, got %v", err)
	}

	// Test List with cancelled context
	_, err = storage.List(ctx, "test/")
	if err != context.Canceled {
		t.Errorf("expected context.Canceled, got %v", err)
	}
}

func TestInmemStorage_FailureFlags(t *testing.T) {
	logger := logger.NewZerologLogger(logger.DefaultConfig())
	storage, err := NewDirectInmem(nil, logger)
	if err != nil {
		t.Fatalf("failed to create inmem storage: %v", err)
	}

	inmem := storage.(*InmemStorage)
	ctx := context.Background()

	entry := &physical.Entry{
		Key:   "test/key",
		Value: []byte("test value"),
	}

	// Test FailPut
	inmem.FailPut(true)
	err = inmem.Put(ctx, entry)
	if err != ErrPutDisabled {
		t.Errorf("expected ErrPutDisabled, got %v", err)
	}
	inmem.FailPut(false)
	err = inmem.Put(ctx, entry)
	if err != nil {
		t.Errorf("expected nil error after disabling FailPut, got %v", err)
	}

	// Test FailGet
	inmem.FailGet(true)
	_, err = inmem.Get(ctx, "test/key")
	if err != ErrGetDisabled {
		t.Errorf("expected ErrGetDisabled, got %v", err)
	}
	inmem.FailGet(false)
	_, err = inmem.Get(ctx, "test/key")
	if err != nil {
		t.Errorf("expected nil error after disabling FailGet, got %v", err)
	}

	// Test FailDelete
	inmem.FailDelete(true)
	err = inmem.Delete(ctx, "test/key")
	if err != ErrDeleteDisabled {
		t.Errorf("expected ErrDeleteDisabled, got %v", err)
	}
	inmem.FailDelete(false)
	err = inmem.Delete(ctx, "test/key")
	if err != nil {
		t.Errorf("expected nil error after disabling FailDelete, got %v", err)
	}

	// Test FailList
	inmem.FailList(true)
	_, err = inmem.List(ctx, "test/")
	if err != ErrListDisabled {
		t.Errorf("expected ErrListDisabled, got %v", err)
	}
	inmem.FailList(false)
	_, err = inmem.List(ctx, "test/")
	if err != nil {
		t.Errorf("expected nil error after disabling FailList, got %v", err)
	}
}

func TestInmemStorage_MaxValueSize(t *testing.T) {
	logger := logger.NewZerologLogger(logger.DefaultConfig())
	config := map[string]string{
		"max_value_size": "100",
	}
	storage, err := NewInmem(config, logger)
	if err != nil {
		t.Fatalf("failed to create inmem storage: %v", err)
	}

	ctx := context.Background()

	// Test value that's too large
	largeEntry := &physical.Entry{
		Key:   "test/large",
		Value: make([]byte, 200),
	}

	err = storage.Put(ctx, largeEntry)
	if err == nil {
		t.Error("expected error for value too large")
	}
	if err != nil && err.Error() != physical.ErrValueTooLarge {
		t.Errorf("expected ErrValueTooLarge, got %v", err)
	}

	// Test value that's within limit
	smallEntry := &physical.Entry{
		Key:   "test/small",
		Value: make([]byte, 50),
	}

	err = storage.Put(ctx, smallEntry)
	if err != nil {
		t.Errorf("expected nil error for small value, got %v", err)
	}
}

func TestInmemStorage_Concurrency(t *testing.T) {
	logger := logger.NewZerologLogger(logger.DefaultConfig())
	storage, err := NewInmem(nil, logger)
	if err != nil {
		t.Fatalf("failed to create inmem storage: %v", err)
	}

	ctx := context.Background()
	var wg sync.WaitGroup
	concurrency := 50

	// Concurrent writes
	wg.Add(concurrency)
	for i := 0; i < concurrency; i++ {
		go func(idx int) {
			defer wg.Done()
			entry := &physical.Entry{
				Key:   fmt.Sprintf("test/key-%d", idx),
				Value: []byte(fmt.Sprintf("value-%d", idx)),
			}
			if err := storage.Put(ctx, entry); err != nil {
				t.Errorf("failed to put entry %d: %v", idx, err)
			}
		}(i)
	}
	wg.Wait()

	// Concurrent reads
	wg.Add(concurrency)
	for i := 0; i < concurrency; i++ {
		go func(idx int) {
			defer wg.Done()
			result, err := storage.Get(ctx, fmt.Sprintf("test/key-%d", idx))
			if err != nil {
				t.Errorf("failed to get entry %d: %v", idx, err)
			}
			if result == nil {
				t.Errorf("expected entry %d, got nil", idx)
			}
		}(i)
	}
	wg.Wait()
}

func TestTransactionalInmemStorage_BasicTransaction(t *testing.T) {
	logger := logger.NewZerologLogger(logger.DefaultConfig())
	storage, err := NewInmem(nil, logger)
	if err != nil {
		t.Fatalf("failed to create inmem storage: %v", err)
	}

	txStorage, ok := storage.(physical.TransactionalStorage)
	if !ok {
		t.Fatal("storage does not support transactions")
	}

	ctx := context.Background()

	// Begin transaction
	tx, err := txStorage.BeginTx(ctx)
	if err != nil {
		t.Fatalf("failed to begin transaction: %v", err)
	}

	// Put in transaction
	entry := &physical.Entry{
		Key:   "test/txkey",
		Value: []byte("tx value"),
	}
	if err := tx.Put(ctx, entry); err != nil {
		t.Fatalf("failed to put in transaction: %v", err)
	}

	// Verify in transaction
	result, err := tx.Get(ctx, "test/txkey")
	if err != nil {
		t.Fatalf("failed to get in transaction: %v", err)
	}
	if !reflect.DeepEqual(result.Value, entry.Value) {
		t.Errorf("expected value %v in tx, got %v", entry.Value, result.Value)
	}

	// Verify not visible outside transaction yet
	result, err = storage.Get(ctx, "test/txkey")
	if err != nil {
		t.Fatalf("failed to get from storage: %v", err)
	}
	if result != nil {
		t.Error("entry should not be visible outside transaction before commit")
	}

	// Commit transaction
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("failed to commit transaction: %v", err)
	}

	// Verify visible after commit
	result, err = storage.Get(ctx, "test/txkey")
	if err != nil {
		t.Fatalf("failed to get from storage after commit: %v", err)
	}
	if result == nil {
		t.Fatal("entry should be visible after commit")
	}
	if !reflect.DeepEqual(result.Value, entry.Value) {
		t.Errorf("expected value %v after commit, got %v", entry.Value, result.Value)
	}
}

func TestTransactionalInmemStorage_Rollback(t *testing.T) {
	logger := logger.NewZerologLogger(logger.DefaultConfig())
	storage, err := NewInmem(nil, logger)
	if err != nil {
		t.Fatalf("failed to create inmem storage: %v", err)
	}

	txStorage, ok := storage.(physical.TransactionalStorage)
	if !ok {
		t.Fatal("storage does not support transactions")
	}

	ctx := context.Background()

	// Put initial value
	initialEntry := &physical.Entry{
		Key:   "test/rollback",
		Value: []byte("initial value"),
	}
	if err := storage.Put(ctx, initialEntry); err != nil {
		t.Fatalf("failed to put initial entry: %v", err)
	}

	// Begin transaction
	tx, err := txStorage.BeginTx(ctx)
	if err != nil {
		t.Fatalf("failed to begin transaction: %v", err)
	}

	// Update in transaction
	updatedEntry := &physical.Entry{
		Key:   "test/rollback",
		Value: []byte("updated value"),
	}
	if err := tx.Put(ctx, updatedEntry); err != nil {
		t.Fatalf("failed to put in transaction: %v", err)
	}

	// Rollback transaction
	if err := tx.Rollback(ctx); err != nil {
		t.Fatalf("failed to rollback transaction: %v", err)
	}

	// Verify original value is unchanged
	result, err := storage.Get(ctx, "test/rollback")
	if err != nil {
		t.Fatalf("failed to get from storage: %v", err)
	}
	if !reflect.DeepEqual(result.Value, initialEntry.Value) {
		t.Errorf("expected original value %v after rollback, got %v", initialEntry.Value, result.Value)
	}
}

func TestTransactionalInmemStorage_ReadOnlyTransaction(t *testing.T) {
	logger := logger.NewZerologLogger(logger.DefaultConfig())
	storage, err := NewInmem(nil, logger)
	if err != nil {
		t.Fatalf("failed to create inmem storage: %v", err)
	}

	txStorage, ok := storage.(physical.TransactionalStorage)
	if !ok {
		t.Fatal("storage does not support transactions")
	}

	ctx := context.Background()

	// Put initial value
	entry := &physical.Entry{
		Key:   "test/readonly",
		Value: []byte("readonly value"),
	}
	if err := storage.Put(ctx, entry); err != nil {
		t.Fatalf("failed to put entry: %v", err)
	}

	// Begin read-only transaction
	tx, err := txStorage.BeginReadOnlyTx(ctx)
	if err != nil {
		t.Fatalf("failed to begin read-only transaction: %v", err)
	}

	// Verify can read
	result, err := tx.Get(ctx, "test/readonly")
	if err != nil {
		t.Fatalf("failed to get in read-only transaction: %v", err)
	}
	if !reflect.DeepEqual(result.Value, entry.Value) {
		t.Errorf("expected value %v, got %v", entry.Value, result.Value)
	}

	// Verify cannot write
	writeEntry := &physical.Entry{
		Key:   "test/write",
		Value: []byte("write value"),
	}
	err = tx.Put(ctx, writeEntry)
	if err != physical.ErrTransactionReadOnly {
		t.Errorf("expected ErrTransactionReadOnly, got %v", err)
	}

	// Verify cannot delete
	err = tx.Delete(ctx, "test/readonly")
	if err != physical.ErrTransactionReadOnly {
		t.Errorf("expected ErrTransactionReadOnly, got %v", err)
	}

	// Commit (should be no-op for read-only)
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("failed to commit read-only transaction: %v", err)
	}
}

func TestTransactionalInmemStorage_ConflictDetection(t *testing.T) {
	logger := logger.NewZerologLogger(logger.DefaultConfig())
	storage, err := NewInmem(nil, logger)
	if err != nil {
		t.Fatalf("failed to create inmem storage: %v", err)
	}

	txStorage, ok := storage.(physical.TransactionalStorage)
	if !ok {
		t.Fatal("storage does not support transactions")
	}

	ctx := context.Background()

	// Put initial value
	initialEntry := &physical.Entry{
		Key:   "test/conflict",
		Value: []byte("initial value"),
	}
	if err := storage.Put(ctx, initialEntry); err != nil {
		t.Fatalf("failed to put initial entry: %v", err)
	}

	// Begin transaction
	tx, err := txStorage.BeginTx(ctx)
	if err != nil {
		t.Fatalf("failed to begin transaction: %v", err)
	}

	// Update value outside transaction
	conflictEntry := &physical.Entry{
		Key:   "test/conflict",
		Value: []byte("conflicting value"),
	}
	if err := storage.Put(ctx, conflictEntry); err != nil {
		t.Fatalf("failed to put conflicting entry: %v", err)
	}

	// Try to update in transaction
	txEntry := &physical.Entry{
		Key:   "test/conflict",
		Value: []byte("tx value"),
	}
	if err := tx.Put(ctx, txEntry); err != nil {
		t.Fatalf("failed to put in transaction: %v", err)
	}

	// Commit should fail due to conflict
	err = tx.Commit(ctx)
	if err == nil {
		t.Error("expected commit to fail due to conflict")
	}
	if err != nil && err != physical.ErrTransactionCommitFailure {
		// Check if it's wrapped
		if !isTransactionCommitFailure(err) {
			t.Errorf("expected ErrTransactionCommitFailure, got %v", err)
		}
	}

	// Verify storage has the conflicting value
	result, err := storage.Get(ctx, "test/conflict")
	if err != nil {
		t.Fatalf("failed to get from storage: %v", err)
	}
	if !reflect.DeepEqual(result.Value, conflictEntry.Value) {
		t.Errorf("expected conflicting value %v, got %v", conflictEntry.Value, result.Value)
	}
}

func TestTransactionalInmemStorage_DoubleCommit(t *testing.T) {
	logger := logger.NewZerologLogger(logger.DefaultConfig())
	storage, err := NewInmem(nil, logger)
	if err != nil {
		t.Fatalf("failed to create inmem storage: %v", err)
	}

	txStorage, ok := storage.(physical.TransactionalStorage)
	if !ok {
		t.Fatal("storage does not support transactions")
	}

	ctx := context.Background()

	tx, err := txStorage.BeginTx(ctx)
	if err != nil {
		t.Fatalf("failed to begin transaction: %v", err)
	}

	// First commit
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("first commit failed: %v", err)
	}

	// Second commit should fail
	err = tx.Commit(ctx)
	if err != physical.ErrTransactionAlreadyCommitted {
		t.Errorf("expected ErrTransactionAlreadyCommitted, got %v", err)
	}
}

func TestTransactionalInmemStorage_AfterCommitOperations(t *testing.T) {
	logger := logger.NewZerologLogger(logger.DefaultConfig())
	storage, err := NewInmem(nil, logger)
	if err != nil {
		t.Fatalf("failed to create inmem storage: %v", err)
	}

	txStorage, ok := storage.(physical.TransactionalStorage)
	if !ok {
		t.Fatal("storage does not support transactions")
	}

	ctx := context.Background()

	tx, err := txStorage.BeginTx(ctx)
	if err != nil {
		t.Fatalf("failed to begin transaction: %v", err)
	}

	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit failed: %v", err)
	}

	// Try operations after commit
	entry := &physical.Entry{
		Key:   "test/key",
		Value: []byte("value"),
	}

	err = tx.Put(ctx, entry)
	if err != physical.ErrTransactionAlreadyCommitted {
		t.Errorf("expected ErrTransactionAlreadyCommitted for Put, got %v", err)
	}

	_, err = tx.Get(ctx, "test/key")
	if err != physical.ErrTransactionAlreadyCommitted {
		t.Errorf("expected ErrTransactionAlreadyCommitted for Get, got %v", err)
	}

	err = tx.Delete(ctx, "test/key")
	if err != physical.ErrTransactionAlreadyCommitted {
		t.Errorf("expected ErrTransactionAlreadyCommitted for Delete, got %v", err)
	}

	_, err = tx.List(ctx, "test/")
	if err != physical.ErrTransactionAlreadyCommitted {
		t.Errorf("expected ErrTransactionAlreadyCommitted for List, got %v", err)
	}
}

func TestTransactionalInmemStorage_DisabledTransactions(t *testing.T) {
	logger := logger.NewZerologLogger(logger.DefaultConfig())
	config := map[string]string{
		"disable_transactions": "true",
	}
	storage, err := NewInmem(config, logger)
	if err != nil {
		t.Fatalf("failed to create inmem storage: %v", err)
	}

	// Should not support transactions
	_, ok := storage.(physical.TransactionalStorage)
	if ok {
		t.Error("storage should not support transactions when disabled")
	}

	// Should still support basic storage operations
	ctx := context.Background()
	entry := &physical.Entry{
		Key:   "test/key",
		Value: []byte("value"),
	}
	if err := storage.Put(ctx, entry); err != nil {
		t.Errorf("basic Put should work: %v", err)
	}
}

func TestInmemStorage_ListPagination(t *testing.T) {
	logger := logger.NewZerologLogger(logger.DefaultConfig())
	storage, err := NewDirectInmem(nil, logger)
	if err != nil {
		t.Fatalf("failed to create inmem storage: %v", err)
	}

	inmem := storage.(*InmemStorage)
	ctx := context.Background()

	// Create test entries with predictable names
	keys := []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j"}
	for _, key := range keys {
		entry := &physical.Entry{
			Key:   "test/" + key,
			Value: []byte("value"),
		}
		if err := storage.Put(ctx, entry); err != nil {
			t.Fatalf("failed to put entry: %v", err)
		}
	}

	t.Run("first page with limit", func(t *testing.T) {
		result, err := inmem.ListPaginatedInternal(ctx, "test/", "", 5)
		if err != nil {
			t.Fatalf("ListPaginatedInternal failed: %v", err)
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
		result, err := inmem.ListPaginatedInternal(ctx, "test/", "e", 5)
		if err != nil {
			t.Fatalf("ListPaginatedInternal failed: %v", err)
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
		result, err := inmem.ListPaginatedInternal(ctx, "test/", "h", 5)
		if err != nil {
			t.Fatalf("ListPaginatedInternal failed: %v", err)
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
		result, err := inmem.ListPaginatedInternal(ctx, "test/", "", -1)
		if err != nil {
			t.Fatalf("ListPaginatedInternal failed: %v", err)
		}
		if len(result) != 10 {
			t.Fatalf("expected 10 keys, got %d", len(result))
		}
	})

	t.Run("limit larger than results", func(t *testing.T) {
		result, err := inmem.ListPaginatedInternal(ctx, "test/", "", 100)
		if err != nil {
			t.Fatalf("ListPaginatedInternal failed: %v", err)
		}
		if len(result) != 10 {
			t.Fatalf("expected 10 keys, got %d", len(result))
		}
	})

	t.Run("after non-existent key", func(t *testing.T) {
		// "aa" would come after "a" but before "b" in sorted order
		result, err := inmem.ListPaginatedInternal(ctx, "test/", "aa", 5)
		if err != nil {
			t.Fatalf("ListPaginatedInternal failed: %v", err)
		}
		// Should return keys starting from "b"
		expected := []string{"b", "c", "d", "e", "f"}
		if !reflect.DeepEqual(result, expected) {
			t.Fatalf("expected %v, got %v", expected, result)
		}
	})

	t.Run("after last key", func(t *testing.T) {
		result, err := inmem.ListPaginatedInternal(ctx, "test/", "j", 5)
		if err != nil {
			t.Fatalf("ListPaginatedInternal failed: %v", err)
		}
		if len(result) != 0 {
			t.Fatalf("expected 0 keys, got %d", len(result))
		}
	})
}

func TestInmemStorage_ListPage_WithDirectories(t *testing.T) {
	logger := logger.NewZerologLogger(logger.DefaultConfig())
	storage, err := NewInmem(nil, logger)
	if err != nil {
		t.Fatalf("failed to create inmem storage: %v", err)
	}

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
		if err := storage.Put(ctx, entry); err != nil {
			t.Fatalf("Put failed: %v", err)
		}
	}

	t.Run("list with directories first page", func(t *testing.T) {
		result, err := storage.ListPage(ctx, "test/", "", 3)
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
		result, err := storage.ListPage(ctx, "test/", "dir1/", 3)
		if err != nil {
			t.Fatalf("ListPage failed: %v", err)
		}
		expected := []string{"dir2/", "zzz"}
		if !reflect.DeepEqual(result, expected) {
			t.Fatalf("expected %v, got %v", expected, result)
		}
	})
}

func TestInmemStorage_ListPage_EmptyPrefix(t *testing.T) {
	logger := logger.NewZerologLogger(logger.DefaultConfig())
	storage, err := NewInmem(nil, logger)
	if err != nil {
		t.Fatalf("failed to create inmem storage: %v", err)
	}

	ctx := context.Background()

	// Create entries at root level
	entries := []*physical.Entry{
		{Key: "key1", Value: []byte("value1")},
		{Key: "key2", Value: []byte("value2")},
		{Key: "key3", Value: []byte("value3")},
	}

	for _, entry := range entries {
		if err := storage.Put(ctx, entry); err != nil {
			t.Fatalf("Put failed: %v", err)
		}
	}

	result, err := storage.ListPage(ctx, "", "", 2)
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

func TestInmemStorage_ListPage_NonExistentPrefix(t *testing.T) {
	logger := logger.NewZerologLogger(logger.DefaultConfig())
	storage, err := NewInmem(nil, logger)
	if err != nil {
		t.Fatalf("failed to create inmem storage: %v", err)
	}

	ctx := context.Background()

	result, err := storage.ListPage(ctx, "nonexistent/", "", 10)
	if err != nil {
		t.Fatalf("expected no error for non-existent prefix, got %v", err)
	}
	if len(result) != 0 {
		t.Fatalf("expected empty list for non-existent prefix, got %v", result)
	}
}

func TestInmemStorage_ListPage_CancelledContext(t *testing.T) {
	logger := logger.NewZerologLogger(logger.DefaultConfig())
	storage, err := NewInmem(nil, logger)
	if err != nil {
		t.Fatalf("failed to create inmem storage: %v", err)
	}

	// Create some test entries
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		entry := &physical.Entry{
			Key:   fmt.Sprintf("test/key%d", i),
			Value: []byte("value"),
		}
		storage.Put(ctx, entry)
	}

	// Try to list with cancelled context
	cancelledCtx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = storage.ListPage(cancelledCtx, "test/", "", 10)
	if err != context.Canceled {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestTransactionalInmemStorage_ListPage(t *testing.T) {
	logger := logger.NewZerologLogger(logger.DefaultConfig())
	storage, err := NewInmem(nil, logger)
	if err != nil {
		t.Fatalf("failed to create inmem storage: %v", err)
	}

	txStorage, ok := storage.(physical.TransactionalStorage)
	if !ok {
		t.Fatal("storage does not support transactions")
	}

	ctx := context.Background()

	// Create test entries
	for i := 0; i < 10; i++ {
		entry := &physical.Entry{
			Key:   fmt.Sprintf("test/key-%02d", i),
			Value: []byte(fmt.Sprintf("value-%d", i)),
		}
		if err := storage.Put(ctx, entry); err != nil {
			t.Fatalf("failed to put entry: %v", err)
		}
	}

	t.Run("list page in transaction", func(t *testing.T) {
		tx, err := txStorage.BeginTx(ctx)
		if err != nil {
			t.Fatalf("failed to begin transaction: %v", err)
		}

		result, err := tx.ListPage(ctx, "test/", "", 5)
		if err != nil {
			t.Fatalf("ListPage failed: %v", err)
		}
		if len(result) != 5 {
			t.Fatalf("expected 5 keys, got %d", len(result))
		}

		if err := tx.Commit(ctx); err != nil {
			t.Fatalf("failed to commit transaction: %v", err)
		}
	})

	t.Run("list page after commit fails", func(t *testing.T) {
		tx, err := txStorage.BeginTx(ctx)
		if err != nil {
			t.Fatalf("failed to begin transaction: %v", err)
		}

		if err := tx.Commit(ctx); err != nil {
			t.Fatalf("failed to commit transaction: %v", err)
		}

		_, err = tx.ListPage(ctx, "test/", "", 5)
		if err != physical.ErrTransactionAlreadyCommitted {
			t.Fatalf("expected ErrTransactionAlreadyCommitted, got %v", err)
		}
	})

	t.Run("list page in read-only transaction", func(t *testing.T) {
		tx, err := txStorage.BeginReadOnlyTx(ctx)
		if err != nil {
			t.Fatalf("failed to begin read-only transaction: %v", err)
		}

		result, err := tx.ListPage(ctx, "test/", "", 5)
		if err != nil {
			t.Fatalf("ListPage failed: %v", err)
		}
		if len(result) != 5 {
			t.Fatalf("expected 5 keys, got %d", len(result))
		}

		if err := tx.Commit(ctx); err != nil {
			t.Fatalf("failed to commit read-only transaction: %v", err)
		}
	})
}

func TestOpName(t *testing.T) {
	tests := []struct {
		op       int
		expected string
	}{
		{PutInMemOp, "put"},
		{DeleteInMemOp, "delete"},
		{ListInMemOp, "list"},
		{GetInMemOp, "get"},
		{BeginTxInMemOp, "begin-tx"},
		{BeginReadOnlyTxInMemOp, "begin-ro-tx"},
		{CommitTxInMemOp, "commit-tx"},
		{RollbackTxInMemOp, "rollback-tx"},
		{999, "unknown"},
	}

	for _, tt := range tests {
		result := OpName(tt.op)
		if result != tt.expected {
			t.Errorf("OpName(%d) = %s, expected %s", tt.op, result, tt.expected)
		}
	}
}

func TestTransactionalInmemStorage_DeleteInTransaction(t *testing.T) {
	logger := logger.NewZerologLogger(logger.DefaultConfig())
	storage, err := NewInmem(nil, logger)
	if err != nil {
		t.Fatalf("failed to create inmem storage: %v", err)
	}

	txStorage, ok := storage.(physical.TransactionalStorage)
	if !ok {
		t.Fatal("storage does not support transactions")
	}

	ctx := context.Background()

	// Put initial value
	entry := &physical.Entry{
		Key:   "test/delete",
		Value: []byte("delete value"),
	}
	if err := storage.Put(ctx, entry); err != nil {
		t.Fatalf("failed to put entry: %v", err)
	}

	// Begin transaction
	tx, err := txStorage.BeginTx(ctx)
	if err != nil {
		t.Fatalf("failed to begin transaction: %v", err)
	}

	// Delete in transaction
	if err := tx.Delete(ctx, "test/delete"); err != nil {
		t.Fatalf("failed to delete in transaction: %v", err)
	}

	// Verify deleted in transaction
	result, err := tx.Get(ctx, "test/delete")
	if err != nil {
		t.Fatalf("failed to get in transaction: %v", err)
	}
	if result != nil {
		t.Error("entry should be deleted in transaction")
	}

	// Verify still exists outside transaction
	result, err = storage.Get(ctx, "test/delete")
	if err != nil {
		t.Fatalf("failed to get from storage: %v", err)
	}
	if result == nil {
		t.Error("entry should still exist outside transaction before commit")
	}

	// Commit transaction
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("failed to commit transaction: %v", err)
	}

	// Verify deleted after commit
	result, err = storage.Get(ctx, "test/delete")
	if err != nil {
		t.Fatalf("failed to get from storage after commit: %v", err)
	}
	if result != nil {
		t.Error("entry should be deleted after commit")
	}
}

func TestInmemStorage_GetNonExistent(t *testing.T) {
	logger := logger.NewZerologLogger(logger.DefaultConfig())
	storage, err := NewInmem(nil, logger)
	if err != nil {
		t.Fatalf("failed to create inmem storage: %v", err)
	}

	ctx := context.Background()

	result, err := storage.Get(ctx, "nonexistent/key")
	if err != nil {
		t.Fatalf("Get should not return error for non-existent key: %v", err)
	}
	if result != nil {
		t.Error("expected nil for non-existent key")
	}
}

func TestInmemStorage_DeleteNonExistent(t *testing.T) {
	logger := logger.NewZerologLogger(logger.DefaultConfig())
	storage, err := NewInmem(nil, logger)
	if err != nil {
		t.Fatalf("failed to create inmem storage: %v", err)
	}

	ctx := context.Background()

	err = storage.Delete(ctx, "nonexistent/key")
	if err != nil {
		t.Fatalf("Delete should not return error for non-existent key: %v", err)
	}
}

func TestInmemStorage_ListEmpty(t *testing.T) {
	logger := logger.NewZerologLogger(logger.DefaultConfig())
	storage, err := NewInmem(nil, logger)
	if err != nil {
		t.Fatalf("failed to create inmem storage: %v", err)
	}

	ctx := context.Background()

	list, err := storage.List(ctx, "empty/")
	if err != nil {
		t.Fatalf("List should not return error for empty prefix: %v", err)
	}
	if len(list) != 0 {
		t.Errorf("expected empty list, got %v", list)
	}
}

func TestTransactionalInmemStorage_ConcurrentTransactions(t *testing.T) {
	logger := logger.NewZerologLogger(logger.DefaultConfig())
	storage, err := NewInmem(nil, logger)
	if err != nil {
		t.Fatalf("failed to create inmem storage: %v", err)
	}

	txStorage, ok := storage.(physical.TransactionalStorage)
	if !ok {
		t.Fatal("storage does not support transactions")
	}

	ctx := context.Background()
	var wg sync.WaitGroup
	concurrency := 10

	// Run concurrent transactions
	wg.Add(concurrency)
	for i := 0; i < concurrency; i++ {
		go func(idx int) {
			defer wg.Done()

			tx, err := txStorage.BeginTx(ctx)
			if err != nil {
				t.Errorf("failed to begin transaction %d: %v", idx, err)
				return
			}

			entry := &physical.Entry{
				Key:   fmt.Sprintf("concurrent/key-%d", idx),
				Value: []byte(fmt.Sprintf("value-%d", idx)),
			}

			if err := tx.Put(ctx, entry); err != nil {
				t.Errorf("failed to put in transaction %d: %v", idx, err)
				return
			}

			// Small delay to increase chance of overlap
			time.Sleep(time.Millisecond)

			if err := tx.Commit(ctx); err != nil {
				t.Errorf("failed to commit transaction %d: %v", idx, err)
			}
		}(i)
	}
	wg.Wait()

	// Verify all entries were committed
	for i := 0; i < concurrency; i++ {
		result, err := storage.Get(ctx, fmt.Sprintf("concurrent/key-%d", i))
		if err != nil {
			t.Errorf("failed to get entry %d: %v", i, err)
		}
		if result == nil {
			t.Errorf("entry %d should exist after concurrent transactions", i)
		}
	}
}

func TestInmemStorage_InvalidMaxValueSize(t *testing.T) {
	logger := logger.NewZerologLogger(logger.DefaultConfig())
	config := map[string]string{
		"max_value_size": "invalid",
	}
	_, err := NewInmem(config, logger)
	if err == nil {
		t.Error("expected error for invalid max_value_size")
	}
}

// Helper function to check if error is or wraps ErrTransactionCommitFailure
func isTransactionCommitFailure(err error) bool {
	if err == nil {
		return false
	}
	// Check if it's the error itself
	if err == physical.ErrTransactionCommitFailure {
		return true
	}
	// Check if error message contains the commit failure text
	return contains(err.Error(), "transaction commit failed")
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
