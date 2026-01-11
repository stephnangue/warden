package core

import (
	"context"
	"fmt"

	"github.com/openbao/openbao/helper/namespace"
	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
)

// pathPolicies returns the paths for policy operations
func (b *SystemBackend) pathPolicies() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "policies/cbp/" + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeString,
					Description: "The policy name",
					Required:    true,
				},
				"policy": {
					Type:        framework.TypeString,
					Description: "The policy document in HCL or JSON format",
					Required:    true,
				},
				"cas": {
					Type:        framework.TypeInt,
					Description: "Check-and-set parameter for optimistic locking",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.handlePolicyCreate,
					Summary:  "Create a new CBP policy",
				},
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.handlePolicyRead,
					Summary:  "Get CBP policy",
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.handlePolicyUpdate,
					Summary:  "Update CBP policy",
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.handlePolicyDelete,
					Summary:  "Delete a CBP policy",
				},
			},
			HelpSynopsis:    "Manage CBP policies",
			HelpDescription: "Create, read, update, and delete capability-based policies.",
		},
		{
			Pattern: "policies/cbp/?$",
			Fields: map[string]*framework.FieldSchema{
				"prefix": {
					Type:        framework.TypeString,
					Description: "Filter policies by prefix",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.handlePolicyList,
					Summary:  "List all CBP policies",
				},
			},
			HelpSynopsis:    "List CBP policies",
			HelpDescription: "List all capability-based policies in the current namespace.",
		},
	}
}

// handlePolicyCreate handles POST /sys/policies/cbp/{name}
func (b *SystemBackend) handlePolicyCreate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	policyText := d.Get("policy").(string)

	b.logger.Info("creating policy", logger.String("name", name))

	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return logical.ErrorResponse(logical.ErrInternal(err.Error())), nil
	}

	// Parse the policy
	policy, err := ParseCBPPolicy(ns, policyText)
	if err != nil {
		return logical.ErrorResponse(logical.ErrBadRequestf("failed to parse policy: %s", err.Error())), nil
	}

	policy.Name = name
	policy.Type = PolicyTypeCBP

	// Get CAS version if provided
	var casVersion *int
	if cas, ok := d.GetOk("cas"); ok {
		v := cas.(int)
		casVersion = &v
	}

	// Store the policy
	if err := b.core.policyStore.SetPolicy(ctx, policy, casVersion); err != nil {
		return logical.ErrorResponse(err), nil
	}

	return b.respondCreated(map[string]any{
		"name":    name,
		"message": fmt.Sprintf("Successfully created policy %s", name),
	}), nil
}

// handlePolicyRead handles GET /sys/policies/cbp/{name}
func (b *SystemBackend) handlePolicyRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)

	// Get the policy
	policy, err := b.core.policyStore.GetPolicy(ctx, name, PolicyTypeCBP)
	if err != nil {
		return logical.ErrorResponse(err), nil
	}

	if policy == nil {
		return logical.ErrorResponse(logical.ErrNotFound("policy not found")), nil
	}

	return b.respondSuccess(map[string]any{
		"name":         policy.Name,
		"policy":       policy.Raw,
		"data_version": policy.DataVersion,
		"cas_required": policy.CASRequired,
	}), nil
}

// handlePolicyUpdate handles PUT /sys/policies/cbp/{name}
func (b *SystemBackend) handlePolicyUpdate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	policyText := d.Get("policy").(string)

	b.logger.Info("updating policy", logger.String("name", name))

	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return logical.ErrorResponse(logical.ErrInternal(err.Error())), nil
	}

	// Parse the policy
	policy, err := ParseCBPPolicy(ns, policyText)
	if err != nil {
		return logical.ErrorResponse(logical.ErrBadRequestf("failed to parse policy: %s", err.Error())), nil
	}

	policy.Name = name
	policy.Type = PolicyTypeCBP

	// Get CAS version if provided
	var casVersion *int
	if cas, ok := d.GetOk("cas"); ok {
		v := cas.(int)
		casVersion = &v
	}

	// Store the policy
	if err := b.core.policyStore.SetPolicy(ctx, policy, casVersion); err != nil {
		return logical.ErrorResponse(err), nil
	}

	return b.respondSuccess(map[string]any{
		"name":    name,
		"message": fmt.Sprintf("Successfully updated policy %s", name),
	}), nil
}

// handlePolicyDelete handles DELETE /sys/policies/cbp/{name}
func (b *SystemBackend) handlePolicyDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)

	b.logger.Info("deleting policy", logger.String("name", name))

	// Delete the policy
	if err := b.core.policyStore.DeletePolicy(ctx, name, PolicyTypeCBP); err != nil {
		return logical.ErrorResponse(err), nil
	}

	return b.respondSuccess(map[string]any{
		"message": fmt.Sprintf("Successfully deleted policy %s", name),
	}), nil
}

// handlePolicyList handles GET /sys/policies/cbp
func (b *SystemBackend) handlePolicyList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	prefix, _ := d.Get("prefix").(string)

	// List policies
	var policies []string
	var err error

	if prefix != "" {
		policies, err = b.core.policyStore.ListPoliciesWithPrefix(ctx, PolicyTypeCBP, prefix, true)
	} else {
		policies, err = b.core.policyStore.ListPolicies(ctx, PolicyTypeCBP, true)
	}

	if err != nil {
		return logical.ErrorResponse(err), nil
	}

	return b.respondSuccess(map[string]any{
		"keys": policies,
	}), nil
}
