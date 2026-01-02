package core

import (
	"context"
	"testing"

	"github.com/stephnangue/warden/logger"
	"github.com/stretchr/testify/assert"
)

func TestNewSystemBackend(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	core := createTestCore(t)

	backend := NewSystemBackend(core, log)

	assert.NotNil(t, backend)
	assert.Equal(t, core, backend.core)
	assert.Equal(t, log, backend.logger)
	assert.NotNil(t, backend.router)
	assert.NotNil(t, backend.api)
	assert.NotNil(t, backend.handlers)
}

func TestSystemBackend_GetType(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	core := createTestCore(t)
	backend := NewSystemBackend(core, log)

	assert.Equal(t, "system", backend.GetType())
}

func TestSystemBackend_GetClass(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	core := createTestCore(t)
	backend := NewSystemBackend(core, log)

	assert.Equal(t, mountClassSystem, backend.GetClass())
}

func TestSystemBackend_GetDescription(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	core := createTestCore(t)
	backend := NewSystemBackend(core, log)

	description := backend.GetDescription()
	assert.NotEmpty(t, description)
	assert.Contains(t, description, "System backend")
}

func TestSystemBackend_GetAccessor(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	core := createTestCore(t)
	backend := NewSystemBackend(core, log)

	assert.Equal(t, "system", backend.GetAccessor())
}

func TestSystemBackend_Cleanup(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	core := createTestCore(t)
	backend := NewSystemBackend(core, log)

	// Should not panic
	ctx := context.Background()
	backend.Cleanup(ctx)
}

func TestValidateMountPath(t *testing.T) {
	tests := []struct {
		name        string
		path        string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "valid simple path",
			path:        "aws",
			expectError: false,
		},
		{
			name:        "valid path with hyphens",
			path:        "aws-prod-europe",
			expectError: false,
		},
		{
			name:        "valid path with underscores",
			path:        "aws_prod_europe",
			expectError: false,
		},
		{
			name:        "valid nested path with single slash",
			path:        "aws/prod",
			expectError: false,
		},
		{
			name:        "valid nested path with multiple slashes",
			path:        "aws/prod/europe",
			expectError: false,
		},
		{
			name:        "valid nested path with hyphens",
			path:        "aws-prod/europe-west",
			expectError: false,
		},
		{
			name:        "valid nested path with underscores",
			path:        "aws_prod/europe_west",
			expectError: false,
		},
		{
			name:        "valid nested path with mixed separators",
			path:        "aws-prod/europe_west/zone1",
			expectError: false,
		},
		{
			name:        "valid deeply nested path",
			path:        "cloud/providers/aws/regions/us-east-1/accounts/prod",
			expectError: false,
		},
		{
			name:        "invalid path starts with sys",
			path:        "sys",
			expectError: true,
			errorMsg:    "reserved prefix",
		},
		{
			name:        "invalid path starts with auth",
			path:        "auth",
			expectError: true,
			errorMsg:    "reserved prefix",
		},
		{
			name:        "invalid path starts with audit",
			path:        "audit",
			expectError: true,
			errorMsg:    "reserved prefix",
		},
		{
			name:        "invalid path starts with hyphen",
			path:        "-aws",
			expectError: true,
			errorMsg:    "cannot start with hyphen or underscore",
		},
		{
			name:        "invalid path starts with underscore",
			path:        "_aws",
			expectError: true,
			errorMsg:    "cannot start with hyphen or underscore",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateMountPath(tt.path)
			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
