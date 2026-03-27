// Copyright (c) 2024 Warden Project
// SPDX-License-Identifier: MPL-2.0

package cert

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/logical"
)

// =============================================================================
// Factory Tests
// =============================================================================

func TestFactory_BasicCreation(t *testing.T) {
	ctx := context.Background()
	conf := &logical.BackendConfig{
		Logger: testLogger(),
	}

	backend, err := Factory(ctx, conf)
	require.NoError(t, err)
	require.NotNil(t, backend)
}

func TestFactory_BackendType(t *testing.T) {
	ctx := context.Background()
	conf := &logical.BackendConfig{
		Logger: testLogger(),
	}

	backend, err := Factory(ctx, conf)
	require.NoError(t, err)
	assert.Equal(t, "cert", backend.Type())
}

func TestFactory_SpecialPaths(t *testing.T) {
	ctx := context.Background()
	conf := &logical.BackendConfig{
		Logger: testLogger(),
	}

	backend, err := Factory(ctx, conf)
	require.NoError(t, err)

	paths := backend.SpecialPaths()
	require.NotNil(t, paths)
	assert.Contains(t, paths.Unauthenticated, "login")
}

