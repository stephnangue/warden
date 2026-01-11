package core

import (
	"context"
	"testing"

	"github.com/openbao/openbao/helper/namespace"
	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
)

// setupTestSystemBackend creates a SystemBackend with mocked dependencies for testing
func setupTestSystemBackend(t *testing.T) (*SystemBackend, context.Context, *Core) {
	t.Helper()

	// Use the existing createTestCore helper
	core := createTestCore(t)

	// Create test context with root namespace
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	return core.systemBackend, ctx, core
}

// createFieldData creates FieldData for testing with the given schema and raw data
func createFieldData(schema map[string]*framework.FieldSchema, raw map[string]interface{}) *framework.FieldData {
	return &framework.FieldData{
		Schema: schema,
		Raw:    raw,
	}
}

// createTestRequest creates a logical.Request for testing
func createTestRequest(operation logical.Operation, path string, data map[string]interface{}) *logical.Request {
	return &logical.Request{
		Operation: operation,
		Path:      path,
		Data:      data,
	}
}

// testError implements error for testing
type testError struct {
	msg string
}

func newTestError(msg string) error {
	return &testError{msg: msg}
}

func (e *testError) Error() string {
	return e.msg
}
