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
Usage: warden policy write <name> <policy_file>

  Writes a capability-based policy. The policy can be read from a file
  or from stdin by using "-" as the filename.

  Examples:

    Write a policy from stdin:

      $ warden policy write my-policy - <<EOF
      path "secret/data/myapp/*" {
        capabilities = ["create", "read", "update", "delete", "list"]
      }

      path "secret/metadata/myapp/*" {
        capabilities = ["list", "read", "delete"]
      }
      EOF

    Write a policy from a file:

      $ warden policy write my-policy ./policy.hcl
`,
	Args: cobra.ExactArgs(2),
	RunE: runWrite,
}

func runWrite(cmd *cobra.Command, args []string) error {
	name := args[0]
	policyPath := args[1]

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
		return fmt.Errorf("policy content cannot be empty")
	}

	// Create the client
	c, err := helpers.Client()
	if err != nil {
		return err
	}

	// Write the policy
	err = c.Sys().PutPolicy(name, policyContent)
	if err != nil {
		return fmt.Errorf("error writing policy: %w", err)
	}

	fmt.Printf("Success! Uploaded policy: %s\n", name)
	return nil
}
