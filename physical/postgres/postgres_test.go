package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/openbao/openbao/sdk/v2/database/helper/dbutil"
	"github.com/openbao/openbao/sdk/v2/physical"
	"github.com/stephnangue/warden/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createMockStorage creates a PostgreSQLStorage with a mocked database connection
func createMockStorage(t *testing.T) (*PostgreSQLStorage, sqlmock.Sqlmock, func()) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	require.NoError(t, err)

	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})

	storage := &PostgreSQLStorage{
		table:  `"test_table"`,
		client: db,
		putQuery: `INSERT INTO "test_table" VALUES($1, $2, $3, $4)` +
			` ON CONFLICT (path, key) DO ` +
			` UPDATE SET (parent_path, path, key, value) = ($1, $2, $3, $4)`,
		getQuery:    `SELECT value FROM "test_table" WHERE path = $1 AND key = $2`,
		deleteQuery: `DELETE FROM "test_table" WHERE path = $1 AND key = $2`,
		listQuery: `SELECT key FROM "test_table" WHERE path = $1` +
			` UNION ALL SELECT DISTINCT substring(substr(path, length($1)+1) from '^.*?/') FROM "test_table"` +
			` WHERE parent_path LIKE $1 || '%'` +
			` ORDER BY key`,
		listPageQuery: `SELECT key FROM "test_table" WHERE path = $1 AND key > $2` +
			` UNION ALL SELECT DISTINCT substring(substr(path, length($1)+1) from '^.*?/') FROM "test_table"` +
			` WHERE parent_path LIKE $1 || '%' AND substring(substr(path, length($1)+1) from '^.*?/') > $2` +
			` ORDER BY key`,
		listPageLimitedQuery: `SELECT key FROM "test_table" WHERE path = $1 AND key > $2` +
			` UNION ALL SELECT DISTINCT substring(substr(path, length($1)+1) from '^.*?/') FROM "test_table"` +
			` WHERE parent_path LIKE $1 || '%' AND substring(substr(path, length($1)+1) from '^.*?/') > $2` +
			` ORDER BY key LIMIT $3`,
		haTable:                  `"test_ha_table"`,
		haGetLockValueQuery:      ` SELECT ha_value FROM "test_ha_table" WHERE NOW() <= valid_until AND ha_key = $1 `,
		haUpsertLockIdentityExec: ` INSERT INTO "test_ha_table" as t (ha_identity, ha_key, ha_value, valid_until) VALUES ($1, $2, $3, NOW() + $4 * INTERVAL '1 seconds'  ) ` + ` ON CONFLICT (ha_key) DO ` + ` UPDATE SET (ha_identity, ha_key, ha_value, valid_until) = ($1, $2, $3, NOW() + $4 * INTERVAL '1 seconds') ` + ` WHERE (t.valid_until < NOW() AND t.ha_key = $2)`,
		haRenewLockIdentityExec:  ` UPDATE "test_ha_table" SET (ha_identity, ha_key, ha_value, valid_until) = ($1, $2, $3, NOW() + $4 * INTERVAL '1 seconds')  WHERE (ha_identity = $1 AND ha_key = $2)  `,
		haDeleteLockExec:         ` DELETE FROM "test_ha_table" WHERE ha_identity=$1 AND ha_key=$2 `,
		haCheckLockHeldQuery:     ` SELECT COUNT(*) FROM "test_ha_table" WHERE  ha_identity=$1 AND ha_key=$2 AND ha_value=$3 AND valid_until > NOW()  `,
		logger:                   log,
		haEnabled:                true,
		txnPermitPool:            physical.NewPermitPool(10),
		fence:                    nil,
	}

	cleanup := func() {
		db.Close()
	}

	return storage, mock, cleanup
}

func TestPostgreSQLStorage_Put(t *testing.T) {
	storage, mock, cleanup := createMockStorage(t)
	defer cleanup()

	ctx := context.Background()

	// Expect the PUT query
	mock.ExpectExec(regexp.QuoteMeta(storage.putQuery)).
		WithArgs("", "/", "testkey", []byte("testvalue")).
		WillReturnResult(sqlmock.NewResult(1, 1))

	entry := &physical.Entry{
		Key:   "testkey",
		Value: []byte("testvalue"),
	}

	err := storage.Put(ctx, entry)
	require.NoError(t, err)

	// Verify all expectations were met
	err = mock.ExpectationsWereMet()
	assert.NoError(t, err)
}

func TestPostgreSQLStorage_Put_Error(t *testing.T) {
	storage, mock, cleanup := createMockStorage(t)
	defer cleanup()

	ctx := context.Background()

	// Expect the PUT query to fail
	mock.ExpectExec(regexp.QuoteMeta(storage.putQuery)).
		WithArgs("", "/", "testkey", []byte("testvalue")).
		WillReturnError(errors.New("database error"))

	entry := &physical.Entry{
		Key:   "testkey",
		Value: []byte("testvalue"),
	}

	err := storage.Put(ctx, entry)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "database error")

	err = mock.ExpectationsWereMet()
	assert.NoError(t, err)
}

func TestPostgreSQLStorage_Get(t *testing.T) {
	storage, mock, cleanup := createMockStorage(t)
	defer cleanup()

	ctx := context.Background()

	// Expect the GET query
	rows := sqlmock.NewRows([]string{"value"}).
		AddRow([]byte("testvalue"))

	mock.ExpectQuery(regexp.QuoteMeta(storage.getQuery)).
		WithArgs("/", "testkey").
		WillReturnRows(rows)

	entry, err := storage.Get(ctx, "testkey")
	require.NoError(t, err)
	require.NotNil(t, entry)
	assert.Equal(t, "testkey", entry.Key)
	assert.Equal(t, []byte("testvalue"), entry.Value)

	err = mock.ExpectationsWereMet()
	assert.NoError(t, err)
}

func TestPostgreSQLStorage_Get_NotFound(t *testing.T) {
	storage, mock, cleanup := createMockStorage(t)
	defer cleanup()

	ctx := context.Background()

	// Expect the GET query to return no rows
	mock.ExpectQuery(regexp.QuoteMeta(storage.getQuery)).
		WithArgs("/", "nonexistent").
		WillReturnError(sql.ErrNoRows)

	entry, err := storage.Get(ctx, "nonexistent")
	require.NoError(t, err)
	assert.Nil(t, entry)

	err = mock.ExpectationsWereMet()
	assert.NoError(t, err)
}

func TestPostgreSQLStorage_Delete(t *testing.T) {
	storage, mock, cleanup := createMockStorage(t)
	defer cleanup()

	ctx := context.Background()

	// Expect the DELETE query
	mock.ExpectExec(regexp.QuoteMeta(storage.deleteQuery)).
		WithArgs("/", "testkey").
		WillReturnResult(sqlmock.NewResult(0, 1))

	err := storage.Delete(ctx, "testkey")
	require.NoError(t, err)

	err = mock.ExpectationsWereMet()
	assert.NoError(t, err)
}

func TestPostgreSQLStorage_List(t *testing.T) {
	storage, mock, cleanup := createMockStorage(t)
	defer cleanup()

	ctx := context.Background()

	// Expect the LIST query
	rows := sqlmock.NewRows([]string{"key"}).
		AddRow("bar/").
		AddRow("test")

	mock.ExpectQuery(regexp.QuoteMeta(storage.listQuery)).
		WithArgs("/foo/").
		WillReturnRows(rows)

	keys, err := storage.List(ctx, "foo/")
	require.NoError(t, err)
	assert.Equal(t, []string{"bar/", "test"}, keys)

	err = mock.ExpectationsWereMet()
	assert.NoError(t, err)
}

func TestPostgreSQLStorage_ListPage(t *testing.T) {
	storage, mock, cleanup := createMockStorage(t)
	defer cleanup()

	ctx := context.Background()

	// Expect the ListPage query with limit
	rows := sqlmock.NewRows([]string{"key"}).
		AddRow("key01").
		AddRow("key02").
		AddRow("key03")

	mock.ExpectQuery(regexp.QuoteMeta(storage.listPageLimitedQuery)).
		WithArgs("/prefix/", "key00", 3).
		WillReturnRows(rows)

	keys, err := storage.ListPage(ctx, "prefix/", "key00", 3)
	require.NoError(t, err)
	assert.Equal(t, []string{"key01", "key02", "key03"}, keys)

	err = mock.ExpectationsWereMet()
	assert.NoError(t, err)
}

func TestPostgreSQLStorage_ListPage_NoLimit(t *testing.T) {
	storage, mock, cleanup := createMockStorage(t)
	defer cleanup()

	ctx := context.Background()

	// Expect the ListPage query without limit
	rows := sqlmock.NewRows([]string{"key"}).
		AddRow("key01").
		AddRow("key02")

	mock.ExpectQuery(regexp.QuoteMeta(storage.listPageQuery)).
		WithArgs("/prefix/", "key00").
		WillReturnRows(rows)

	keys, err := storage.ListPage(ctx, "prefix/", "key00", -1)
	require.NoError(t, err)
	assert.Equal(t, []string{"key01", "key02"}, keys)

	err = mock.ExpectationsWereMet()
	assert.NoError(t, err)
}

func TestPostgreSQLStorage_SplitKey(t *testing.T) {
	storage, _, cleanup := createMockStorage(t)
	defer cleanup()

	tests := []struct {
		name               string
		input              string
		expectedParentPath string
		expectedPath       string
		expectedKey        string
	}{
		{
			name:               "single level",
			input:              "key",
			expectedParentPath: "",
			expectedPath:       "/",
			expectedKey:        "key",
		},
		{
			name:               "two levels",
			input:              "foo/bar",
			expectedParentPath: "/",
			expectedPath:       "/foo/",
			expectedKey:        "bar",
		},
		{
			name:               "three levels",
			input:              "foo/bar/baz",
			expectedParentPath: "/foo/",
			expectedPath:       "/foo/bar/",
			expectedKey:        "baz",
		},
		{
			name:               "deep nesting",
			input:              "a/b/c/d/e",
			expectedParentPath: "/a/b/c/",
			expectedPath:       "/a/b/c/d/",
			expectedKey:        "e",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parentPath, path, key := storage.splitKey(tt.input)
			assert.Equal(t, tt.expectedParentPath, parentPath)
			assert.Equal(t, tt.expectedPath, path)
			assert.Equal(t, tt.expectedKey, key)
		})
	}
}

func TestPostgreSQLStorage_ReadOnlyTransaction(t *testing.T) {
	storage, mock, cleanup := createMockStorage(t)
	defer cleanup()

	ctx := context.Background()

	// Expect BeginTx
	mock.ExpectBegin()

	txn, err := storage.BeginReadOnlyTx(ctx)
	require.NoError(t, err)
	require.NotNil(t, txn)

	// Test Get in transaction
	rows := sqlmock.NewRows([]string{"value"}).
		AddRow([]byte("value1"))

	mock.ExpectQuery(regexp.QuoteMeta(storage.getQuery)).
		WithArgs("/", "key1").
		WillReturnRows(rows)

	entry, err := txn.Get(ctx, "key1")
	require.NoError(t, err)
	require.NotNil(t, entry)
	assert.Equal(t, []byte("value1"), entry.Value)

	// Test Put should fail
	err = txn.Put(ctx, &physical.Entry{Key: "key2", Value: []byte("value2")})
	assert.ErrorIs(t, err, physical.ErrTransactionReadOnly)

	// Test Delete should fail
	err = txn.Delete(ctx, "key1")
	assert.ErrorIs(t, err, physical.ErrTransactionReadOnly)

	// Commit (will rollback for read-only)
	mock.ExpectRollback()
	err = txn.Commit(ctx)
	require.NoError(t, err)

	err = mock.ExpectationsWereMet()
	assert.NoError(t, err)
}

func TestPostgreSQLStorage_ReadWriteTransaction(t *testing.T) {
	storage, mock, cleanup := createMockStorage(t)
	defer cleanup()

	ctx := context.Background()

	// Expect BeginTx
	mock.ExpectBegin()

	txn, err := storage.BeginTx(ctx)
	require.NoError(t, err)
	require.NotNil(t, txn)

	// Test Put in transaction
	mock.ExpectExec(regexp.QuoteMeta(storage.putQuery)).
		WithArgs("", "/", "key1", []byte("value1")).
		WillReturnResult(sqlmock.NewResult(1, 1))

	err = txn.Put(ctx, &physical.Entry{Key: "key1", Value: []byte("value1")})
	require.NoError(t, err)

	// Test Get in transaction
	rows := sqlmock.NewRows([]string{"value"}).
		AddRow([]byte("value1"))

	mock.ExpectQuery(regexp.QuoteMeta(storage.getQuery)).
		WithArgs("/", "key1").
		WillReturnRows(rows)

	entry, err := txn.Get(ctx, "key1")
	require.NoError(t, err)
	require.NotNil(t, entry)
	assert.Equal(t, []byte("value1"), entry.Value)

	// Commit transaction
	mock.ExpectCommit()

	err = txn.Commit(ctx)
	require.NoError(t, err)

	err = mock.ExpectationsWereMet()
	assert.NoError(t, err)
}

func TestPostgreSQLStorage_TransactionRollback(t *testing.T) {
	storage, mock, cleanup := createMockStorage(t)
	defer cleanup()

	ctx := context.Background()

	// Expect BeginTx
	mock.ExpectBegin()

	txn, err := storage.BeginTx(ctx)
	require.NoError(t, err)

	// Put some data
	mock.ExpectExec(regexp.QuoteMeta(storage.putQuery)).
		WithArgs("", "/", "key1", []byte("value1")).
		WillReturnResult(sqlmock.NewResult(1, 1))

	err = txn.Put(ctx, &physical.Entry{Key: "key1", Value: []byte("value1")})
	require.NoError(t, err)

	// Rollback transaction
	mock.ExpectRollback()

	err = txn.Rollback(ctx)
	require.NoError(t, err)

	err = mock.ExpectationsWereMet()
	assert.NoError(t, err)
}

func TestPostgreSQLStorage_TransactionDelete(t *testing.T) {
	storage, mock, cleanup := createMockStorage(t)
	defer cleanup()

	ctx := context.Background()

	// Begin transaction
	mock.ExpectBegin()

	txn, err := storage.BeginTx(ctx)
	require.NoError(t, err)

	// Delete in transaction
	mock.ExpectExec(regexp.QuoteMeta(storage.deleteQuery)).
		WithArgs("/", "key1").
		WillReturnResult(sqlmock.NewResult(0, 1))

	err = txn.Delete(ctx, "key1")
	require.NoError(t, err)

	// Commit
	mock.ExpectCommit()

	err = txn.Commit(ctx)
	require.NoError(t, err)

	err = mock.ExpectationsWereMet()
	assert.NoError(t, err)
}

func TestPostgreSQLStorage_TransactionList(t *testing.T) {
	storage, mock, cleanup := createMockStorage(t)
	defer cleanup()

	ctx := context.Background()

	// Begin transaction
	mock.ExpectBegin()

	txn, err := storage.BeginReadOnlyTx(ctx)
	require.NoError(t, err)

	// List in transaction
	rows := sqlmock.NewRows([]string{"key"}).
		AddRow("key1").
		AddRow("key2")

	mock.ExpectQuery(regexp.QuoteMeta(storage.listQuery)).
		WithArgs("/prefix/").
		WillReturnRows(rows)

	keys, err := txn.List(ctx, "prefix/")
	require.NoError(t, err)
	assert.Equal(t, []string{"key1", "key2"}, keys)

	// Commit
	mock.ExpectRollback()

	err = txn.Commit(ctx)
	require.NoError(t, err)

	err = mock.ExpectationsWereMet()
	assert.NoError(t, err)
}

func TestPostgreSQLStorage_TransactionListPage(t *testing.T) {
	storage, mock, cleanup := createMockStorage(t)
	defer cleanup()

	ctx := context.Background()

	// Begin transaction
	mock.ExpectBegin()

	txn, err := storage.BeginReadOnlyTx(ctx)
	require.NoError(t, err)

	// ListPage in transaction
	rows := sqlmock.NewRows([]string{"key"}).
		AddRow("key2").
		AddRow("key3")

	mock.ExpectQuery(regexp.QuoteMeta(storage.listPageLimitedQuery)).
		WithArgs("/prefix/", "key1", 2).
		WillReturnRows(rows)

	keys, err := txn.ListPage(ctx, "prefix/", "key1", 2)
	require.NoError(t, err)
	assert.Equal(t, []string{"key2", "key3"}, keys)

	// Commit
	mock.ExpectRollback()

	err = txn.Commit(ctx)
	require.NoError(t, err)

	err = mock.ExpectationsWereMet()
	assert.NoError(t, err)
}

func TestPostgreSQLStorage_TransactionAlreadyCommitted(t *testing.T) {
	storage, mock, cleanup := createMockStorage(t)
	defer cleanup()

	ctx := context.Background()

	// Begin transaction
	mock.ExpectBegin()

	txn, err := storage.BeginTx(ctx)
	require.NoError(t, err)

	// Commit transaction (without writes, so it will rollback)
	mock.ExpectRollback()

	err = txn.Commit(ctx)
	require.NoError(t, err)

	// Try to use transaction after commit
	err = txn.Put(ctx, &physical.Entry{Key: "key", Value: []byte("value")})
	assert.ErrorIs(t, err, physical.ErrTransactionAlreadyCommitted)

	_, err = txn.Get(ctx, "key")
	assert.ErrorIs(t, err, physical.ErrTransactionAlreadyCommitted)

	err = txn.Delete(ctx, "key")
	assert.ErrorIs(t, err, physical.ErrTransactionAlreadyCommitted)

	_, err = txn.List(ctx, "")
	assert.ErrorIs(t, err, physical.ErrTransactionAlreadyCommitted)

	_, err = txn.ListPage(ctx, "", "", 10)
	assert.ErrorIs(t, err, physical.ErrTransactionAlreadyCommitted)

	// Try to commit again
	err = txn.Commit(ctx)
	assert.ErrorIs(t, err, physical.ErrTransactionAlreadyCommitted)

	err = mock.ExpectationsWereMet()
	assert.NoError(t, err)
}

func TestPostgreSQLStorage_TransactionEmptyCommit(t *testing.T) {
	storage, mock, cleanup := createMockStorage(t)
	defer cleanup()

	ctx := context.Background()

	// Begin transaction
	mock.ExpectBegin()

	txn, err := storage.BeginTx(ctx)
	require.NoError(t, err)

	// Commit without any writes (should rollback)
	mock.ExpectRollback()

	err = txn.Commit(ctx)
	require.NoError(t, err)

	err = mock.ExpectationsWereMet()
	assert.NoError(t, err)
}

func TestPostgreSQLStorage_TransactionUpdate(t *testing.T) {
	storage, mock, cleanup := createMockStorage(t)
	defer cleanup()

	ctx := context.Background()

	// Begin transaction
	mock.ExpectBegin()

	txn, err := storage.BeginTx(ctx)
	require.NoError(t, err)

	// Update (upsert)
	mock.ExpectExec(regexp.QuoteMeta(storage.putQuery)).
		WithArgs("", "/", "key1", []byte("updated_value")).
		WillReturnResult(sqlmock.NewResult(1, 1))

	err = txn.Put(ctx, &physical.Entry{Key: "key1", Value: []byte("updated_value")})
	require.NoError(t, err)

	// Commit
	mock.ExpectCommit()

	err = txn.Commit(ctx)
	require.NoError(t, err)

	err = mock.ExpectationsWereMet()
	assert.NoError(t, err)
}

func TestPostgreSQLStorage_TransactionalInterface(t *testing.T) {
	storage, _, cleanup := createMockStorage(t)
	defer cleanup()

	// Verify it implements TransactionalStorage
	_, ok := interface{}(storage).(physical.TransactionalBackend)
	assert.True(t, ok, "PostgreSQLStorage should implement TransactionalStorage")
}

func TestPostgreSQLStorage_HAEnabled(t *testing.T) {
	storage, _, cleanup := createMockStorage(t)
	defer cleanup()

	// Verify HABackend interface
	haBackend, ok := interface{}(storage).(physical.HABackend)
	require.True(t, ok)

	assert.True(t, haBackend.HAEnabled())
}

func TestPostgreSQLStorage_LockWith(t *testing.T) {
	storage, _, cleanup := createMockStorage(t)
	defer cleanup()

	haBackend, ok := interface{}(storage).(physical.HABackend)
	require.True(t, ok)

	lock, err := haBackend.LockWith("test-key", "test-value")
	require.NoError(t, err)
	require.NotNil(t, lock)

	pgLock, ok := lock.(*PostgreSQLLock)
	require.True(t, ok)
	assert.Equal(t, "test-key", pgLock.key)
	assert.Equal(t, "test-value", pgLock.value)
	assert.Equal(t, PostgreSQLLockTTLSeconds, pgLock.ttlSeconds)
}

func TestPostgreSQLStorage_LockValue_Held(t *testing.T) {
	storage, mock, cleanup := createMockStorage(t)
	defer cleanup()

	haBackend, ok := interface{}(storage).(physical.HABackend)
	require.True(t, ok)

	lock, err := haBackend.LockWith("test-lock", "node1")
	require.NoError(t, err)

	// Mock lock value query - lock is held
	rows := sqlmock.NewRows([]string{"ha_value"}).
		AddRow("node1")

	mock.ExpectQuery(regexp.QuoteMeta(storage.haGetLockValueQuery)).
		WithArgs("test-lock").
		WillReturnRows(rows)

	held, value, err := lock.Value()
	require.NoError(t, err)
	assert.True(t, held)
	assert.Equal(t, "node1", value)

	err = mock.ExpectationsWereMet()
	assert.NoError(t, err)
}

func TestPostgreSQLStorage_LockValue_NotHeld(t *testing.T) {
	storage, mock, cleanup := createMockStorage(t)
	defer cleanup()

	haBackend, ok := interface{}(storage).(physical.HABackend)
	require.True(t, ok)

	lock, err := haBackend.LockWith("test-lock", "node1")
	require.NoError(t, err)

	// Mock lock value query - no rows (lock not held)
	mock.ExpectQuery(regexp.QuoteMeta(storage.haGetLockValueQuery)).
		WithArgs("test-lock").
		WillReturnError(sql.ErrNoRows)

	held, value, err := lock.Value()
	require.NoError(t, err)
	assert.False(t, held)
	assert.Equal(t, "", value)

	err = mock.ExpectationsWereMet()
	assert.NoError(t, err)
}

func TestPostgreSQLStorage_LockUnlock(t *testing.T) {
	storage, mock, cleanup := createMockStorage(t)
	defer cleanup()

	haBackend, ok := interface{}(storage).(physical.HABackend)
	require.True(t, ok)

	lock, err := haBackend.LockWith("test-lock", "node1")
	require.NoError(t, err)

	pgLock := lock.(*PostgreSQLLock)

	// Mock unlock query
	mock.ExpectExec(regexp.QuoteMeta(storage.haDeleteLockExec)).
		WithArgs(pgLock.identity, "test-lock").
		WillReturnResult(sqlmock.NewResult(0, 1))

	err = lock.Unlock()
	require.NoError(t, err)

	err = mock.ExpectationsWereMet()
	assert.NoError(t, err)
}

func TestPostgreSQLStorage_IsActivelyHeld_True(t *testing.T) {
	storage, mock, cleanup := createMockStorage(t)
	defer cleanup()

	ctx := context.Background()

	haBackend, ok := interface{}(storage).(physical.HABackend)
	require.True(t, ok)

	lock, err := haBackend.LockWith("test-lock", "node1")
	require.NoError(t, err)

	pgLock := lock.(*PostgreSQLLock)

	// Mock check lock held query - returns 1 (held)
	rows := sqlmock.NewRows([]string{"count"}).
		AddRow(1)

	mock.ExpectQuery(regexp.QuoteMeta(storage.haCheckLockHeldQuery)).
		WithArgs(pgLock.identity, "test-lock", "node1").
		WillReturnRows(rows)

	isHeld, err := pgLock.IsActivelyHeld(ctx)
	require.NoError(t, err)
	assert.True(t, isHeld)

	err = mock.ExpectationsWereMet()
	assert.NoError(t, err)
}

func TestPostgreSQLStorage_IsActivelyHeld_False(t *testing.T) {
	storage, mock, cleanup := createMockStorage(t)
	defer cleanup()

	ctx := context.Background()

	haBackend, ok := interface{}(storage).(physical.HABackend)
	require.True(t, ok)

	lock, err := haBackend.LockWith("test-lock", "node1")
	require.NoError(t, err)

	pgLock := lock.(*PostgreSQLLock)

	// Mock check lock held query - returns 0 (not held)
	rows := sqlmock.NewRows([]string{"count"}).
		AddRow(0)

	mock.ExpectQuery(regexp.QuoteMeta(storage.haCheckLockHeldQuery)).
		WithArgs(pgLock.identity, "test-lock", "node1").
		WillReturnRows(rows)

	isHeld, err := pgLock.IsActivelyHeld(ctx)
	require.NoError(t, err)
	assert.False(t, isHeld)

	err = mock.ExpectationsWereMet()
	assert.NoError(t, err)
}

func TestPostgreSQLStorage_QuoteIdentifier(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "simple name",
			input:    "table",
			expected: `"table"`,
		},
		{
			name:     "name with quotes",
			input:    `my"table`,
			expected: `"my""table"`,
		},
		{
			name:     "name with null byte",
			input:    "table\x00stuff",
			expected: `"table"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := dbutil.QuoteIdentifier(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestPostgreSQLStorage_ConnectionURL(t *testing.T) {
	// Test environment variable takes precedence
	expectedURL := "postgres://test:test@localhost/testdb"
	t.Setenv("WARDEN_PG_CONNECTION_URL", expectedURL)

	conf := map[string]string{
		"connection_url": "postgres://wrong:wrong@localhost/wrongdb",
	}

	url := connectionURL(conf)
	assert.Equal(t, expectedURL, url)

	// Test config value used when env not set
	t.Setenv("WARDEN_PG_CONNECTION_URL", "")
	url = connectionURL(conf)
	assert.Equal(t, conf["connection_url"], url)
}

func TestPostgreSQLStorage_TransactionBatchOperations(t *testing.T) {
	storage, mock, cleanup := createMockStorage(t)
	defer cleanup()

	ctx := context.Background()

	// Begin transaction
	mock.ExpectBegin()

	txn, err := storage.BeginTx(ctx)
	require.NoError(t, err)

	// Perform batch operations
	numEntries := 10
	for i := 0; i < numEntries; i++ {
		mock.ExpectExec(regexp.QuoteMeta(storage.putQuery)).
			WithArgs("/txn/batch/", fmt.Sprintf("/txn/batch/key%03d/", i), fmt.Sprintf("key%03d", i), []byte(fmt.Sprintf("value%d", i))).
			WillReturnResult(sqlmock.NewResult(int64(i), 1))
	}

	for i := 0; i < numEntries; i++ {
		err := txn.Put(ctx, &physical.Entry{
			Key:   fmt.Sprintf("txn/batch/key%03d/key%03d", i, i),
			Value: []byte(fmt.Sprintf("value%d", i)),
		})
		require.NoError(t, err)
	}

	// Commit transaction
	mock.ExpectCommit()

	err = txn.Commit(ctx)
	require.NoError(t, err)

	err = mock.ExpectationsWereMet()
	assert.NoError(t, err)
}

func TestPostgreSQLStorage_RegisterActiveNodeLock(t *testing.T) {
	storage, _, cleanup := createMockStorage(t)
	defer cleanup()

	haBackend, ok := interface{}(storage).(physical.FencingHABackend)
	require.True(t, ok)

	lock, err := haBackend.LockWith("active-node", "node1")
	require.NoError(t, err)

	// Register the lock
	err = haBackend.RegisterActiveNodeLock(lock)
	require.NoError(t, err)

	// Verify the fence is set
	storage.fenceLock.RLock()
	defer storage.fenceLock.RUnlock()
	assert.NotNil(t, storage.fence)
	assert.Equal(t, lock, storage.fence)
}

// fakeLock implements physical.Lock for testing wrong type registration
type fakeLock struct{}

func (f *fakeLock) Lock(stopCh <-chan struct{}) (<-chan struct{}, error) {
	return nil, nil
}

func (f *fakeLock) Unlock() error {
	return nil
}

func (f *fakeLock) Value() (bool, string, error) {
	return false, "", nil
}

func TestPostgreSQLStorage_RegisterActiveNodeLock_WrongType(t *testing.T) {
	storage, _, cleanup := createMockStorage(t)
	defer cleanup()

	haBackend, ok := interface{}(storage).(physical.FencingHABackend)
	require.True(t, ok)

	// Try to register a wrong lock type
	lock := &fakeLock{}

	err := haBackend.RegisterActiveNodeLock(lock)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expected PostgreSQLLock")
}

func TestPostgreSQLStorage_ValidateFence_NoFence(t *testing.T) {
	storage, mock, cleanup := createMockStorage(t)
	defer cleanup()

	ctx := context.Background()

	// No fence registered, Put should succeed
	mock.ExpectExec(regexp.QuoteMeta(storage.putQuery)).
		WithArgs("", "/", "key", []byte("value")).
		WillReturnResult(sqlmock.NewResult(1, 1))

	err := storage.Put(ctx, &physical.Entry{Key: "key", Value: []byte("value")})
	require.NoError(t, err)

	err = mock.ExpectationsWereMet()
	assert.NoError(t, err)
}

func TestPostgreSQLStorage_ValidateFence_Held(t *testing.T) {
	storage, mock, cleanup := createMockStorage(t)
	defer cleanup()

	ctx := context.Background()

	haBackend, ok := interface{}(storage).(physical.FencingHABackend)
	require.True(t, ok)

	// Create and register a lock
	lock, err := haBackend.LockWith("active-node", "node1")
	require.NoError(t, err)

	err = haBackend.RegisterActiveNodeLock(lock)
	require.NoError(t, err)

	pgLock := lock.(*PostgreSQLLock)

	// Mock fence validation - lock is held
	rows := sqlmock.NewRows([]string{"count"}).
		AddRow(1)

	mock.ExpectQuery(regexp.QuoteMeta(storage.haCheckLockHeldQuery)).
		WithArgs(pgLock.identity, "active-node", "node1").
		WillReturnRows(rows)

	// Mock Put query
	mock.ExpectExec(regexp.QuoteMeta(storage.putQuery)).
		WithArgs("", "/", "key", []byte("value")).
		WillReturnResult(sqlmock.NewResult(1, 1))

	err = storage.Put(ctx, &physical.Entry{Key: "key", Value: []byte("value")})
	require.NoError(t, err)

	err = mock.ExpectationsWereMet()
	assert.NoError(t, err)
}

func TestPostgreSQLStorage_ValidateFence_NotHeld(t *testing.T) {
	storage, mock, cleanup := createMockStorage(t)
	defer cleanup()

	ctx := context.Background()

	haBackend, ok := interface{}(storage).(physical.FencingHABackend)
	require.True(t, ok)

	// Create and register a lock
	lock, err := haBackend.LockWith("active-node", "node1")
	require.NoError(t, err)

	err = haBackend.RegisterActiveNodeLock(lock)
	require.NoError(t, err)

	pgLock := lock.(*PostgreSQLLock)

	// Mock fence validation - lock is NOT held
	rows := sqlmock.NewRows([]string{"count"}).
		AddRow(0)

	mock.ExpectQuery(regexp.QuoteMeta(storage.haCheckLockHeldQuery)).
		WithArgs(pgLock.identity, "active-node", "node1").
		WillReturnRows(rows)

	// Put should fail due to fence validation
	err = storage.Put(ctx, &physical.Entry{Key: "key", Value: []byte("value")})
	require.Error(t, err)
	assert.Contains(t, err.Error(), physical.ErrFencedWriteFailed)

	err = mock.ExpectationsWereMet()
	assert.NoError(t, err)
}

func TestPostgreSQLStorage_ValidateFence_UnfencedWrite(t *testing.T) {
	storage, mock, cleanup := createMockStorage(t)
	defer cleanup()

	haBackend, ok := interface{}(storage).(physical.FencingHABackend)
	require.True(t, ok)

	// Create and register a lock
	lock, err := haBackend.LockWith("active-node", "node1")
	require.NoError(t, err)

	err = haBackend.RegisterActiveNodeLock(lock)
	require.NoError(t, err)

	// Use unfenced context
	ctx := physical.UnfencedWriteCtx(context.Background())

	// No fence check should occur, Put should proceed directly
	mock.ExpectExec(regexp.QuoteMeta(storage.putQuery)).
		WithArgs("", "/", "key", []byte("value")).
		WillReturnResult(sqlmock.NewResult(1, 1))

	err = storage.Put(ctx, &physical.Entry{Key: "key", Value: []byte("value")})
	require.NoError(t, err)

	err = mock.ExpectationsWereMet()
	assert.NoError(t, err)
}
