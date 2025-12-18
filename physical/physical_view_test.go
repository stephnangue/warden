package physical

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockStorage is a simple in-memory storage implementation for testing
type mockStorage struct {
	data map[string][]byte
}

func newMockStorage() *mockStorage {
	return &mockStorage{
		data: make(map[string][]byte),
	}
}

func (m *mockStorage) Put(ctx context.Context, entry *Entry) error {
	m.data[entry.Key] = entry.Value
	return nil
}

func (m *mockStorage) Get(ctx context.Context, key string) (*Entry, error) {
	value, ok := m.data[key]
	if !ok {
		return nil, nil
	}
	return &Entry{
		Key:   key,
		Value: value,
	}, nil
}

func (m *mockStorage) Delete(ctx context.Context, key string) error {
	delete(m.data, key)
	return nil
}

func (m *mockStorage) List(ctx context.Context, prefix string) ([]string, error) {
	keys := []string{}
	for k := range m.data {
		if len(prefix) == 0 || k[:len(prefix)] == prefix {
			// Extract the suffix after the prefix
			suffix := k[len(prefix):]
			// Only include immediate children
			if len(suffix) > 0 && !contains(keys, suffix) {
				keys = append(keys, suffix)
			}
		}
	}
	return keys, nil
}

func (m *mockStorage) ListPage(ctx context.Context, prefix string, after string, limit int) ([]string, error) {
	keys, err := m.List(ctx, prefix)
	if err != nil {
		return nil, err
	}

	// Filter keys after the 'after' key
	var result []string
	for _, k := range keys {
		if k > after {
			result = append(result, k)
		}
	}

	// Apply limit if specified
	if limit > 0 && len(result) > limit {
		result = result[:limit]
	}

	return result, nil
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func TestNewView(t *testing.T) {
	backend := newMockStorage()
	prefix := "test/prefix/"

	view := NewView(backend, prefix)

	require.NotNil(t, view)
	assert.Equal(t, backend, view.backend)
	assert.Equal(t, prefix, view.prefix)
}

func TestView_ImplementsStorage(t *testing.T) {
	backend := newMockStorage()
	view := NewView(backend, "test/")

	// Verify it implements Storage interface
	_, ok := interface{}(view).(Storage)
	assert.True(t, ok, "View should implement Storage interface")
}

func TestView_Put(t *testing.T) {
	backend := newMockStorage()
	view := NewView(backend, "auth/")

	ctx := context.Background()

	entry := &Entry{
		Key:   "token/key1",
		Value: []byte("value1"),
	}

	err := view.Put(ctx, entry)
	require.NoError(t, err)

	// Verify data was stored with expanded key in backend
	stored, err := backend.Get(ctx, "auth/token/key1")
	require.NoError(t, err)
	require.NotNil(t, stored)
	assert.Equal(t, []byte("value1"), stored.Value)
}

func TestView_Get(t *testing.T) {
	backend := newMockStorage()
	view := NewView(backend, "secret/")

	ctx := context.Background()

	// Put data directly in backend with full key
	err := backend.Put(ctx, &Entry{
		Key:   "secret/data/key1",
		Value: []byte("secret-value"),
	})
	require.NoError(t, err)

	// Get through view with truncated key
	entry, err := view.Get(ctx, "data/key1")
	require.NoError(t, err)
	require.NotNil(t, entry)
	assert.Equal(t, "data/key1", entry.Key)
	assert.Equal(t, []byte("secret-value"), entry.Value)
}

func TestView_Get_NotFound(t *testing.T) {
	backend := newMockStorage()
	view := NewView(backend, "secret/")

	ctx := context.Background()

	entry, err := view.Get(ctx, "nonexistent")
	require.NoError(t, err)
	assert.Nil(t, entry)
}

func TestView_Delete(t *testing.T) {
	backend := newMockStorage()
	view := NewView(backend, "auth/")

	ctx := context.Background()

	// Put data in backend
	err := backend.Put(ctx, &Entry{
		Key:   "auth/token/key1",
		Value: []byte("value1"),
	})
	require.NoError(t, err)

	// Delete through view
	err = view.Delete(ctx, "token/key1")
	require.NoError(t, err)

	// Verify it's deleted in backend
	entry, err := backend.Get(ctx, "auth/token/key1")
	require.NoError(t, err)
	assert.Nil(t, entry)
}

func TestView_List(t *testing.T) {
	backend := newMockStorage()
	view := NewView(backend, "config/")

	ctx := context.Background()

	// Put multiple entries
	entries := []string{
		"config/database/postgres",
		"config/database/mysql",
		"config/cache/redis",
	}

	for _, key := range entries {
		err := backend.Put(ctx, &Entry{
			Key:   key,
			Value: []byte("value"),
		})
		require.NoError(t, err)
	}

	// List through view
	keys, err := view.List(ctx, "")
	require.NoError(t, err)
	assert.Contains(t, keys, "database/postgres")
	assert.Contains(t, keys, "database/mysql")
	assert.Contains(t, keys, "cache/redis")
}

func TestView_ListPage(t *testing.T) {
	backend := newMockStorage()
	view := NewView(backend, "items/")

	ctx := context.Background()

	// Put multiple entries
	for i := 1; i <= 5; i++ {
		err := backend.Put(ctx, &Entry{
			Key:   "items/key" + string(rune('0'+i)),
			Value: []byte("value"),
		})
		require.NoError(t, err)
	}

	// List page with limit
	keys, err := view.ListPage(ctx, "", "key1", 3)
	require.NoError(t, err)
	assert.LessOrEqual(t, len(keys), 3)
}

func TestView_ListPage_NoLimit(t *testing.T) {
	backend := newMockStorage()
	view := NewView(backend, "items/")

	ctx := context.Background()

	// Put multiple entries
	for i := 1; i <= 5; i++ {
		err := backend.Put(ctx, &Entry{
			Key:   "items/key" + string(rune('0'+i)),
			Value: []byte("value"),
		})
		require.NoError(t, err)
	}

	// List page without limit
	keys, err := view.ListPage(ctx, "", "key1", -1)
	require.NoError(t, err)
	assert.Greater(t, len(keys), 0)
}

func TestView_SanityCheck_RelativePath(t *testing.T) {
	backend := newMockStorage()
	view := NewView(backend, "test/")

	ctx := context.Background()

	// Test Put with relative path
	err := view.Put(ctx, &Entry{
		Key:   "foo/../bar",
		Value: []byte("value"),
	})
	assert.ErrorIs(t, err, ErrRelativePath)

	// Test Get with relative path
	_, err = view.Get(ctx, "foo/../bar")
	assert.ErrorIs(t, err, ErrRelativePath)

	// Test Delete with relative path
	err = view.Delete(ctx, "foo/../bar")
	assert.ErrorIs(t, err, ErrRelativePath)

	// Test List with relative path
	_, err = view.List(ctx, "foo/../bar")
	assert.ErrorIs(t, err, ErrRelativePath)

	// Test ListPage with relative path
	_, err = view.ListPage(ctx, "foo/../bar", "", -1)
	assert.ErrorIs(t, err, ErrRelativePath)
}

func TestView_ExpandKey(t *testing.T) {
	tests := []struct {
		name     string
		prefix   string
		suffix   string
		expected string
	}{
		{
			name:     "simple prefix",
			prefix:   "auth/",
			suffix:   "token",
			expected: "auth/token",
		},
		{
			name:     "nested prefix",
			prefix:   "secret/data/",
			suffix:   "key1",
			expected: "secret/data/key1",
		},
		{
			name:     "empty suffix",
			prefix:   "config/",
			suffix:   "",
			expected: "config/",
		},
		{
			name:     "complex path",
			prefix:   "sys/",
			suffix:   "mounts/database/config",
			expected: "sys/mounts/database/config",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend := newMockStorage()
			view := NewView(backend, tt.prefix)

			result := view.expandKey(tt.suffix)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestView_TruncateKey(t *testing.T) {
	tests := []struct {
		name     string
		prefix   string
		full     string
		expected string
	}{
		{
			name:     "simple truncation",
			prefix:   "auth/",
			full:     "auth/token",
			expected: "token",
		},
		{
			name:     "nested truncation",
			prefix:   "secret/data/",
			full:     "secret/data/key1",
			expected: "key1",
		},
		{
			name:     "no match",
			prefix:   "config/",
			full:     "other/key",
			expected: "other/key",
		},
		{
			name:     "exact match",
			prefix:   "sys/",
			full:     "sys/",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend := newMockStorage()
			view := NewView(backend, tt.prefix)

			result := view.truncateKey(tt.full)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestView_MultipleViews(t *testing.T) {
	backend := newMockStorage()
	authView := NewView(backend, "auth/")
	secretView := NewView(backend, "secret/")

	ctx := context.Background()

	// Put data through auth view
	err := authView.Put(ctx, &Entry{
		Key:   "token/key1",
		Value: []byte("auth-value"),
	})
	require.NoError(t, err)

	// Put data through secret view
	err = secretView.Put(ctx, &Entry{
		Key:   "data/key1",
		Value: []byte("secret-value"),
	})
	require.NoError(t, err)

	// Verify backend has both with correct prefixes
	authEntry, err := backend.Get(ctx, "auth/token/key1")
	require.NoError(t, err)
	require.NotNil(t, authEntry)
	assert.Equal(t, []byte("auth-value"), authEntry.Value)

	secretEntry, err := backend.Get(ctx, "secret/data/key1")
	require.NoError(t, err)
	require.NotNil(t, secretEntry)
	assert.Equal(t, []byte("secret-value"), secretEntry.Value)

	// Verify views return isolated data
	authData, err := authView.Get(ctx, "token/key1")
	require.NoError(t, err)
	require.NotNil(t, authData)
	assert.Equal(t, []byte("auth-value"), authData.Value)

	secretData, err := secretView.Get(ctx, "data/key1")
	require.NoError(t, err)
	require.NotNil(t, secretData)
	assert.Equal(t, []byte("secret-value"), secretData.Value)

	// Verify cross-access doesn't work
	noData, err := authView.Get(ctx, "data/key1")
	require.NoError(t, err)
	assert.Nil(t, noData)
}

func TestView_NestedViews(t *testing.T) {
	backend := newMockStorage()
	parentView := NewView(backend, "parent/")
	childView := NewView(parentView, "child/")

	ctx := context.Background()

	// Put through nested view
	err := childView.Put(ctx, &Entry{
		Key:   "key1",
		Value: []byte("nested-value"),
	})
	require.NoError(t, err)

	// Verify in backend with fully expanded key
	entry, err := backend.Get(ctx, "parent/child/key1")
	require.NoError(t, err)
	require.NotNil(t, entry)
	assert.Equal(t, []byte("nested-value"), entry.Value)

	// Verify through parent view
	parentEntry, err := parentView.Get(ctx, "child/key1")
	require.NoError(t, err)
	require.NotNil(t, parentEntry)
	assert.Equal(t, []byte("nested-value"), parentEntry.Value)

	// Verify through child view
	childEntry, err := childView.Get(ctx, "key1")
	require.NoError(t, err)
	require.NotNil(t, childEntry)
	assert.Equal(t, []byte("nested-value"), childEntry.Value)
	assert.Equal(t, "key1", childEntry.Key)
}

func TestView_EmptyPrefix(t *testing.T) {
	backend := newMockStorage()
	view := NewView(backend, "")

	ctx := context.Background()

	// Put through view with empty prefix
	err := view.Put(ctx, &Entry{
		Key:   "key1",
		Value: []byte("value1"),
	})
	require.NoError(t, err)

	// Get through view
	entry, err := view.Get(ctx, "key1")
	require.NoError(t, err)
	require.NotNil(t, entry)
	assert.Equal(t, "key1", entry.Key)
	assert.Equal(t, []byte("value1"), entry.Value)

	// Verify in backend
	backendEntry, err := backend.Get(ctx, "key1")
	require.NoError(t, err)
	require.NotNil(t, backendEntry)
	assert.Equal(t, []byte("value1"), backendEntry.Value)
}

func TestView_PutGetDeleteCycle(t *testing.T) {
	backend := newMockStorage()
	view := NewView(backend, "test/")

	ctx := context.Background()

	key := "mykey"
	value := []byte("myvalue")

	// Put
	err := view.Put(ctx, &Entry{
		Key:   key,
		Value: value,
	})
	require.NoError(t, err)

	// Get
	entry, err := view.Get(ctx, key)
	require.NoError(t, err)
	require.NotNil(t, entry)
	assert.Equal(t, key, entry.Key)
	assert.Equal(t, value, entry.Value)

	// Delete
	err = view.Delete(ctx, key)
	require.NoError(t, err)

	// Verify deleted
	entry, err = view.Get(ctx, key)
	require.NoError(t, err)
	assert.Nil(t, entry)
}

func TestView_GetReturnsNewEntry(t *testing.T) {
	backend := newMockStorage()
	view := NewView(backend, "prefix/")

	ctx := context.Background()

	// Put entry
	originalValue := []byte("original")
	err := view.Put(ctx, &Entry{
		Key:   "key1",
		Value: originalValue,
	})
	require.NoError(t, err)

	// Get entry
	entry, err := view.Get(ctx, "key1")
	require.NoError(t, err)
	require.NotNil(t, entry)

	// Verify we get a new Entry instance (not just the truncated key)
	assert.Equal(t, "key1", entry.Key)
	assert.Equal(t, originalValue, entry.Value)

	// Verify modifying the returned entry doesn't affect storage
	entry.Value[0] = 'X'

	// Get again to verify original is unchanged
	entry2, err := view.Get(ctx, "key1")
	require.NoError(t, err)
	require.NotNil(t, entry2)
	assert.Equal(t, originalValue, entry2.Value)
}
