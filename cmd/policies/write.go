package policies

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/cmd/helpers"
)

var WriteCmd = &cobra.Command{
	Use:           "write <name> <policy_file>",
	SilenceUsage:  true,
	SilenceErrors: true,
	Short:         "Write a policy",
	Long: `
Usage: warden policy write <name> <policy_file> [flags]

  Writes a policy. The policy can be read from a file or from stdin by using
  "-" as the filename. Use -type to choose which kind of policy to write:
  "cbp" (default) grants capabilities on paths, "mcp" constrains the JSON-RPC
  methods, tools, resources and prompts reachable on a path.

  Policy names are unique across types: a name already used by a policy of the
  other type is rejected.

  Examples:

    Write a capability-based policy from stdin:

      $ warden policy write my-policy - <<EOF
      path "secret/data/myapp/*" {
        capabilities = ["create", "read", "update", "delete", "list"]
      }

      path "secret/metadata/myapp/*" {
        capabilities = ["list", "read", "delete"]
      }
      EOF

    Write an MCP policy from stdin. Rules are grouped by what they govern,
    and each family block names what it allows and denies:

      $ warden policy write -type mcp github-tools - <<EOF
      path "mcp/gateway/github/*" {
        methods {
          allowed = ["tools/list", "tools/call"]
        }

        tools {
          allowed = ["get_repository", "list_issues"]
          denied  = ["delete_*", "force_*"]
        }

        condition = "call.args.?env.orValue('') != 'prod'"
      }
      EOF

    Write a policy from a file:

      $ warden policy write my-policy ./policy.hcl
`,
	Args: cobra.ExactArgs(2),
	RunE: runWrite,
}

func init() {
	addTypeFlag(WriteCmd)
}

func runWrite(cmd *cobra.Command, args []string) error {
	name := args[0]
	policyPath := args[1]
	if err := helpers.ValidatePath(name); err != nil {
		return err
	}

	pType, err := resolvePolicyType()
	if err != nil {
		return err
	}

	// Read policy content
	var policyContent string
	if policyPath == "-" {
		// Read from stdin
		bytes, err := io.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("failed to read from stdin: %w", err)
		}
		policyContent = string(bytes)
	} else {
		// Read from file
		bytes, err := os.ReadFile(policyPath)
		if err != nil {
			return fmt.Errorf("failed to read policy file: %w", err)
		}
		policyContent = string(bytes)
	}

	if policyContent == "" {
		return fmt.Errorf("policy content cannot be empty: %w", helpers.ErrInvalidInput)
	}

	// Create the client
	c, err := helpers.Client()
	if err != nil {
		return err
	}

	if helpers.ResolveDryRun() {
		payload := map[string]any{"policy": policyContent}
		return helpers.DryRun(c, "PUT", "sys/policies/"+pType+"/{name}", payload)
	}

	// Write the policy
	err = c.Sys().PutPolicyOfType(pType, name, policyContent)
	if err != nil {
		return fmt.Errorf("error writing policy: %w", err)
	}

	return helpers.RenderMap(map[string]any{"name": name, "type": pType, "written": true}, func() {
		fmt.Printf("Success! Uploaded %s policy: %s\n", pType, name)
	})
}
