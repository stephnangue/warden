package core

import (
	"context"
	"errors"
	"net/http"

	"github.com/stephnangue/warden/logical"
)

// renderGatewayFailure lets the provider that owns a gateway request answer a
// failure in its clients' native wire format, instead of Warden's generic JSON
// error, which an SDK built for the upstream cannot parse.
//
// The failures it covers happen in core before the provider ever sees the
// request — transparent auth, the policy check, credential issuance — so core has
// to hand them over; the provider owns everything about the answer. Core only
// dispatches: it never inspects what comes back.
//
// It runs before the response is audited, so the audit records exactly the
// status and body the client receives — the same swap-before-audit technique
// userChallengeForDeny uses. The original error rides on the returned response's
// Err, so the audit's Error field keeps its text even though the error is
// returned as nil (the rendered response is now the answer, not an error the
// HTTP layer should format).
//
// It is a no-op unless all hold: the request is a gateway (streamed) request;
// the backend has not already written the response; the error is not a standby
// redirect, which the HTTP layer must still act on; there is a failure; and the
// owning backend implements logical.GatewayErrorRenderer and does not decline.
//
// routePath is req.Path as it was before routing. Routing rewrites req.Path
// relative to the mount and leaves it so, and a failure can come back after
// that, so req.Path no longer finds the owning backend.
func (c *Core) renderGatewayFailure(ctx context.Context, req *logical.Request, routePath string, resp *logical.Response, err error) (*logical.Response, error) {
	if req == nil || !req.Streamed || (resp != nil && resp.Streamed) {
		return resp, err
	}

	var status int
	var cause error
	switch {
	case err != nil:
		if errors.Is(err, ErrStandby) {
			return resp, err
		}
		status, cause = logical.GetErrorCode(err), err
	case resp != nil && resp.Err != nil:
		status, cause = resp.StatusCode, resp.Err
		if status < http.StatusBadRequest {
			status = logical.GetErrorCode(cause)
		}
	default:
		return resp, err
	}

	renderer, ok := c.router.MatchingBackend(ctx, routePath).(logical.GatewayErrorRenderer)
	if !ok {
		return resp, err
	}
	out := renderer.RenderGatewayError(req, &logical.GatewayFailure{
		Class:     logical.ClassifyGatewayFailure(status, cause),
		Status:    status,
		Err:       cause,
		RequestID: req.RequestID,
	})
	if out == nil {
		return resp, err
	}

	// Keep any header core attached to the original answer (a challenge, say)
	// unless the renderer set that header itself.
	if resp != nil && len(resp.Headers) > 0 {
		if out.Headers == nil {
			out.Headers = make(http.Header, len(resp.Headers))
		}
		for k, v := range resp.Headers {
			if _, set := out.Headers[k]; !set {
				out.Headers[k] = v
			}
		}
	}
	if out.MountClass == "" && resp != nil {
		out.MountClass = resp.MountClass
	}
	out.Err = cause
	return out, nil
}
