// Copyright (c) 2024 Warden Project
// SPDX-License-Identifier: MPL-2.0

package core

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStreamedStatusCode(t *testing.T) {
	// A captured status always wins, even if the context later errored.
	assert.Equal(t, http.StatusOK, streamedStatusCode(http.StatusOK, nil))
	assert.Equal(t, http.StatusOK, streamedStatusCode(http.StatusOK, context.Canceled))
	assert.Equal(t, http.StatusForbidden, streamedStatusCode(http.StatusForbidden, context.DeadlineExceeded))

	// Nothing written + client hung up → 499.
	assert.Equal(t, statusClientClosedRequest, streamedStatusCode(0, context.Canceled))
	// Wrapped cancellation still resolves (errors.Is traversal).
	assert.Equal(t, statusClientClosedRequest, streamedStatusCode(0, fmt.Errorf("ctx: %w", context.Canceled)))

	// Nothing written + upstream deadline → 504.
	assert.Equal(t, http.StatusGatewayTimeout, streamedStatusCode(0, context.DeadlineExceeded))

	// Nothing written and no context error → outcome unknown, preserve 0.
	assert.Equal(t, 0, streamedStatusCode(0, nil))
}
