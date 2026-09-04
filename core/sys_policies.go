package core

import (
	"context"
	"fmt"
	"strings"

	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
)

// pathPolicies returns the paths for policy operations, one set per policy
// type. CBP policies grant capabilities on paths; MCP policies are purely
// restrictive tool contracts whose rules are ANDed with the CBP decision.
func (b *SystemBackend) pathPolicies() []*framework.Path {
	var paths []*framework.Path
	for _, policyType := range []PolicyType{PolicyTypeCBP, PolicyTypeMCP} {
		paths = append(paths, b.policyPaths(policyType)...)
	}

	return paths
}

// policyPaths builds the CRUD and list paths for one policy type. Everything
// but the storage type and the help text is identical between types, so the
// handlers are closures over the type rather than duplicated bodies.
func (b *SystemBackend) policyPaths(policyType PolicyType) []*framework.Path {
	name := policyType.String()
	label := strings.ToUpper(name)

	return []*framework.Path{
		{
			Pattern: "policies/" + name + "/" + framework.GenericNameRegex("name"),
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
				"cas_required": {
					Type:        framework.TypeBool,
					Description: "Require every write to this policy to carry a matching 'cas'. Persisted with the policy, and taken from each write: send false alongside a valid 'cas' to lift it.",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.handlePolicyCreate(policyType),
					Summary:  "Create a new " + label + " policy",
				},
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.handlePolicyRead(policyType),
					Summary:  "Get " + label + " policy",
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.handlePolicyUpdate(policyType),
					Summary:  "Update " + label + " policy",
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.handlePolicyDelete(policyType),
					Summary:  "Delete a " + label + " policy",
				},
			},
			HelpSynopsis:    "Manage " + label + " policies",
			HelpDescription: policyHelpDescription(policyType),
		},
		{
			Pattern: "policies/" + name + "/?$",
			Fields: map[string]*framework.FieldSchema{
				"prefix": {
					Type:        framework.TypeString,
					Description: "Filter policies by prefix",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.handlePolicyList(policyType),
					Summary:  "List all " + label + " policies",
				},
			},
			HelpSynopsis:    "List " + label + " policies",
			HelpDescription: "List all " + label + " policies in the current namespace.",
		},
	}
}

func policyHelpDescription(policyType PolicyType) string {
	switch policyType {
	case PolicyTypeMCP:
		return "Create, read, update, and delete MCP policies. An MCP policy constrains " +
			"the JSON-RPC methods, tool names, resource URIs and prompt names reachable on " +
			"a path. It never grants access on its own: the request must already be allowed " +
			"by a capability-based policy."
	default:
		return "Create, read, update, and delete capability-based policies."
	}
}

// parsePolicyForType parses a policy document with the parser matching its type.
func parsePolicyForType(ns *namespace.Namespace, policyText string, policyType PolicyType) (*Policy, error) {
	switch policyType {
	case PolicyTypeMCP:
		return ParseMCPPolicy(ns, policyText)
	default:
		return ParseCBPPolicy(ns, policyText)
	}
}

// handlePolicyCreate handles POST /sys/policies/{type}/{name}
func (b *SystemBackend) handlePolicyCreate(policyType PolicyType) framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
		name := d.Get("name").(string)
		policyText := d.Get("policy").(string)

		b.logger.Info("creating policy", logger.String("name", name), logger.String("type", policyType.String()))

		ns, err := namespace.FromContext(ctx)
		if err != nil {
			return logical.ErrorResponse(logical.ErrInternal(err.Error())), nil
		}

		// Parse the policy
		policy, err := parsePolicyForType(ns, policyText, policyType)
		if err != nil {
			return logical.ErrorResponse(logical.ErrBadRequestf("failed to parse policy: %s", err.Error())), nil
		}

		policy.Name = name
		policy.Type = policyType

		// Get CAS version if provided
		var casVersion *int
		if cas, ok := d.GetOk("cas"); ok {
			v := cas.(int)
			casVersion = &v
		}

		// Taken from the request on every write rather than carried over, so a policy
		// that requires check-and-set can also stop requiring it — the store still
		// demands a matching cas for the write that lifts the flag.
		policy.CASRequired = d.Get("cas_required").(bool)

		// Store the policy
		if err := b.core.policyStore.SetPolicy(ctx, policy, casVersion); err != nil {
			return logical.ErrorResponse(err), nil
		}

		return b.respondCreated(map[string]any{
			"name":    name,
			"message": fmt.Sprintf("Successfully created policy %s", name),
		}), nil
	}
}

// handlePolicyRead handles GET /sys/policies/{type}/{name}
func (b *SystemBackend) handlePolicyRead(policyType PolicyType) framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
		name := d.Get("name").(string)

		// Get the policy
		policy, err := b.core.policyStore.GetPolicy(ctx, name, policyType)
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
}

// handlePolicyUpdate handles PUT /sys/policies/{type}/{name}
func (b *SystemBackend) handlePolicyUpdate(policyType PolicyType) framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
		name := d.Get("name").(string)
		policyText := d.Get("policy").(string)

		b.logger.Info("updating policy", logger.String("name", name), logger.String("type", policyType.String()))

		ns, err := namespace.FromContext(ctx)
		if err != nil {
			return logical.ErrorResponse(logical.ErrInternal(err.Error())), nil
		}

		// Parse the policy
		policy, err := parsePolicyForType(ns, policyText, policyType)
		if err != nil {
			return logical.ErrorResponse(logical.ErrBadRequestf("failed to parse policy: %s", err.Error())), nil
		}

		policy.Name = name
		policy.Type = policyType

		// Get CAS version if provided
		var casVersion *int
		if cas, ok := d.GetOk("cas"); ok {
			v := cas.(int)
			casVersion = &v
		}

		// Taken from the request on every write rather than carried over, so a policy
		// that requires check-and-set can also stop requiring it — the store still
		// demands a matching cas for the write that lifts the flag.
		policy.CASRequired = d.Get("cas_required").(bool)

		// Store the policy
		if err := b.core.policyStore.SetPolicy(ctx, policy, casVersion); err != nil {
			return logical.ErrorResponse(err), nil
		}

		return b.respondSuccess(map[string]any{
			"name":    name,
			"message": fmt.Sprintf("Successfully updated policy %s", name),
		}), nil
	}
}

// handlePolicyDelete handles DELETE /sys/policies/{type}/{name}
func (b *SystemBackend) handlePolicyDelete(policyType PolicyType) framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
		name := d.Get("name").(string)

		b.logger.Info("deleting policy", logger.String("name", name), logger.String("type", policyType.String()))

		// Delete the policy
		if err := b.core.policyStore.DeletePolicy(ctx, name, policyType); err != nil {
			return logical.ErrorResponse(err), nil
		}

		return b.respondSuccess(map[string]any{
			"message": fmt.Sprintf("Successfully deleted policy %s", name),
		}), nil
	}
}

// handlePolicyList handles GET /sys/policies/{type}
func (b *SystemBackend) handlePolicyList(policyType PolicyType) framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
		prefix, _ := d.Get("prefix").(string)

		// List policies
		var policies []string
		var err error

		if prefix != "" {
			policies, err = b.core.policyStore.ListPoliciesWithPrefix(ctx, policyType, prefix, true)
		} else {
			policies, err = b.core.policyStore.ListPolicies(ctx, policyType, true)
		}

		if err != nil {
			return logical.ErrorResponse(err), nil
		}

		return b.respondSuccess(map[string]any{
			"keys": policies,
		}), nil
	}
}
