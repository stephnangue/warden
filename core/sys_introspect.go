// Copyright (c) 2024 Warden Project
// SPDX-License-Identifier: MPL-2.0

package core

import (
	"context"
	"errors"
	"net/http"

	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
)

// discoveryAdmitConcurrency caps the goroutines one discovery call runs, so a
// namespace whose roles target many auth mounts cannot spawn unbounded work on
// a single call.
const discoveryAdmitConcurrency = 10

// pathIntrospectRoles exposes GET /v1/sys/introspect/roles: the roles of the
// caller's namespace that the presented credential is granted, each at the
// auth mount a request for it would be admitted through (see
// discoverFromAdmissions). An agent discovers which roles it may assume
// without having role names distributed out of band.
func (b *SystemBackend) pathIntrospectRoles() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "introspect/roles",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.handleIntrospectRoles,
					Summary:  "Discover roles the presented identity can assume",
					Description: "Returns {roles, warnings}. roles[] holds the roles a group grants " +
						"the presented credential at the auth mount a request for each role is " +
						"admitted through; each entry is {name, description, skill, provider_path}. " +
						"warnings[] holds one message per auth mount that could not decide. Both " +
						"arrays are sorted and may be empty.",
					Responses: map[int][]framework.Response{
						http.StatusOK: {{
							Description: "Roles the presented identity can assume.",
							MediaType:   "application/json",
							Fields: map[string]*framework.FieldSchema{
								"roles": {
									Type:        framework.TypeSlice,
									Description: "Roles the identity can assume, sorted by name. Each item: {name, description, skill, provider_path}.",
								},
								"warnings": {
									Type:        framework.TypeStringSlice,
									Description: "One entry per auth mount that could not decide (unconfigured, no trust anchors, its verifier unreachable). Format: `mount \"<auth-path>\": <error>`. A mount that does not admit the credential is silent.",
								},
							},
						}},
						http.StatusUnauthorized: {{
							Description: "No JWT bearer token or TLS client certificate was presented.",
						}},
					},
				},
			},
			HelpSynopsis: "Discover roles the presented identity can assume",
			HelpDescription: "Admits the presented credential once at each auth mount a role of the " +
				"current namespace is reached through (its provider's auto_auth_path, or the " +
				"namespace's auto_auth_path for a role without a usable provider) and returns " +
				"the roles a group grants it there. The output names roles only, never a " +
				"group, a fact or an auth mount.",
		},
	}
}

// handleIntrospectRoles is the sys/introspect/roles handler: {roles, warnings},
// each role {name, description, skill, provider_path}, sorted by name. No
// credential is a 401.
//
// Through the request path, the discovery is the one the role-less leg
// already made for this request (requestDiscovery), so the credential is
// admitted once per target mount, not twice.
func (b *SystemBackend) handleIntrospectRoles(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	var d *admissionDiscovery
	var err error
	if discoveryRequestFromContext(ctx) != nil {
		if !hasDiscoveryCredential(req) {
			err = errDiscoveryNoCredential
		} else {
			d, err = b.core.requestDiscovery(ctx)
		}
	} else {
		d, err = b.core.discoverFromAdmissions(ctx, req)
	}
	if errors.Is(err, errDiscoveryNoCredential) || errors.Is(err, errDiscoveryTicket) {
		return &logical.Response{StatusCode: http.StatusUnauthorized, Err: err}, nil
	}
	if err == nil && d == nil {
		err = errDiscoveryFailed
	}
	if err != nil {
		return logical.ErrorResponse(logical.ErrInternal(err.Error())), nil
	}
	roles := make([]admittedRole, len(d.granted))
	for i, r := range d.granted {
		roles[i] = admittedRole{
			Name:         r.Name,
			Description:  r.Description,
			Skill:        r.Skill,
			ProviderPath: r.ProviderPath,
		}
	}
	return b.respondSuccess(map[string]any{
		"roles":    roles,
		"warnings": d.warnings,
	}), nil
}
