package policies

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/api"
	"github.com/stephnangue/warden/cmd/helpers"
)

// policyType holds the value of the shared -type flag. Every policy
// subcommand binds the same variable; only one of them runs per invocation.
var policyType string

// addTypeFlag registers the shared -type flag on a policy subcommand.
func addTypeFlag(cmd *cobra.Command) {
	cmd.Flags().StringVar(&policyType, "type", api.PolicyTypeCBP,
		"Policy type: cbp (capability-based) or mcp (MCP tool contract)")
}

// resolvePolicyType validates the -type flag and returns the path segment the
// API expects. Validating here rather than at the server keeps a typo from
// looking like a missing policy.
func resolvePolicyType() (string, error) {
	switch policyType {
	case api.PolicyTypeCBP, api.PolicyTypeMCP:
		return policyType, nil
	default:
		return "", fmt.Errorf("invalid policy type %q, want %q or %q: %w",
			policyType, api.PolicyTypeCBP, api.PolicyTypeMCP, helpers.ErrInvalidInput)
	}
}
