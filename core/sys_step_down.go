// Copyright (c) 2024 Warden Project
// SPDX-License-Identifier: MPL-2.0

package core

import (
	"context"
	"errors"
	"net/http"

	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
)

// pathStepDown exposes PUT/POST /v1/sys/step-down: the active node gives up
// leadership so a standby can take over. It is a root path (root token or
// sudo) and unavailable in namespaces (restrictedSysAPIs).
func (b *SystemBackend) pathStepDown() []*framework.Path {
	op := &framework.PathOperation{
		Callback: b.handleStepDown,
		Summary:  "Force the active node to step down",
		Description: "Makes the active node give up leadership so that a standby can acquire " +
			"it. Answers 204 once the request is accepted; the step-down starts after the " +
			"response, so the request and its response are both audited before teardown.",
		Responses: map[int][]framework.Response{
			http.StatusNoContent:  {{Description: "Step-down accepted."}},
			http.StatusBadRequest: {{Description: "HA is not enabled, or the request names a namespace."}},
		},
	}
	return []*framework.Path{
		{
			Pattern: "step-down",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: op,
				logical.CreateOperation: op,
			},
			HelpSynopsis: "Force the active node to step down",
			HelpDescription: "The active node gives up leadership and a standby acquires it. A " +
				"step-down sent to a standby is forwarded to the active node. Requires the root " +
				"token or a sudo grant, in the root namespace.",
		},
	}
}

// handleStepDown accepts a step-down and starts it once the request is done.
//
// Teardown takes the state lock and stops the audit broker, and a request
// holds neither, so stepping down from inside the handler would race the
// response's audit entry. The handler therefore only arms the step-down: it
// fires when the HTTP request's context ends, which net/http does after the
// handler chain returns, by when the response entry is written. A client that
// disconnects after this point still steps the node down: the request was
// authorized and audited, so the command stands.
//
// The active context is captured here, on the request goroutine, rather than
// read from the goroutine later: unseal replaces it, and a seal or shutdown
// before the request completes cancels it, which drops the step-down instead
// of leaking the goroutine.
func (b *SystemBackend) handleStepDown(_ context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	c := b.core
	if !c.HAEnabled() {
		return logical.ErrorResponse(logical.ErrBadRequest("HA not enabled")), nil
	}

	if req.HTTPRequest == nil {
		if err := c.StepDown(); err != nil {
			return nil, err
		}
		return nil, nil
	}

	active := c.activeContext
	done := req.HTTPRequest.Context().Done()
	go func() {
		select {
		case <-done:
		case <-active.Done():
			return
		}
		if err := c.StepDown(); err != nil && !errors.Is(err, ErrHANotEnabled) {
			b.logger.Warn("step-down after request failed", logger.Err(err))
		}
	}()
	return nil, nil
}
