package core

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateMountPath_ReservedPrefixes(t *testing.T) {
	tests := []struct {
		path      string
		shouldErr bool
	}{
		{"sys", true},
		{"sys-test", true},
		{"auth", true},
		{"auth-method", true},
		{"audit", true},
		{"audit-device", true},
		{"my-aws", false},
		{"production", false},
		{"aws_dev", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			err := ValidateMountPath(tt.path)
			if tt.shouldErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateMountPath_SpecialCharacters(t *testing.T) {
	tests := []struct {
		path      string
		shouldErr bool
	}{
		{"-test", true},
		{"_test", true},
		{"test-aws", false},
		{"test_aws", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			err := ValidateMountPath(tt.path)
			if tt.shouldErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
