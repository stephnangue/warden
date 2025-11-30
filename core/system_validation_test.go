package core

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

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
			name:        "invalid nested path with single slash",
			path:        "aws/prod",
			expectError: true,
			errorMsg:    "nested paths are not supported",
		},
		{
			name:        "invalid nested path with multiple slashes",
			path:        "aws/prod/europe",
			expectError: true,
			errorMsg:    "nested paths are not supported",
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
