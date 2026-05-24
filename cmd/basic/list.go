package basic

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/cmd/helpers"
)

var (
	listPath string

	ListCmd = &cobra.Command{
		Use:           "list",
		SilenceUsage:  true,
		SilenceErrors: true,
		Short:         "List data from a path",
		Long: `
Usage: warden list [PATH]

  List data from the given path. The PATH may be supplied either
  positionally or via --path (pick one — combining both is rejected).
  The path should be in the format "provider_mount/resource" or
  "auth/auth_mount/resource" or "sys/path/to/resource" and will be
  converted to the appropriate API path.

  Examples:

    List JWT auth roles:

      $ warden list auth/jwt/role
      $ warden list --path=auth/jwt/role

    List providers:

      $ warden list sys/providers

    List namespaces:

      $ warden list sys/namespaces
`,
		Args: cobra.MaximumNArgs(1),
		RunE: runList,
	}
)

func init() {
	ListCmd.Flags().StringVar(&listPath, "path", "", "API path (alternative to the positional PATH argument)")
}

func runList(cmd *cobra.Command, args []string) error {
	path, err := helpers.RequirePath(args, listPath)
	if err != nil {
		return err
	}
	if err := helpers.ValidatePath(path); err != nil {
		return err
	}

	c, err := helpers.Client()
	if err != nil {
		return err
	}

	resource, err := c.Operator().List(path)
	if err != nil {
		return fmt.Errorf("failed to list from %s: %w", path, err)
	}

	if resource == nil || resource.Data == nil {
		fmt.Fprintf(os.Stderr, "No data found at path: %s\n", path)
		return nil
	}

	keys := extractKeys(resource.Data)

	// Table mode keeps the existing "Keys\n  key1\n  key2" layout. Other
	// formats render via the shared helper, which honors --fields.
	if helpers.ResolveFormat() == helpers.FormatTable {
		printKeys(keys)
		return nil
	}
	return helpers.RenderMap(resource.Data, nil)
}

func extractKeys(data map[string]any) []string {
	raw, ok := data["keys"]
	if !ok || raw == nil {
		return nil
	}
	switch v := raw.(type) {
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			out = append(out, fmt.Sprintf("%v", item))
		}
		return out
	}
	return nil
}

func printKeys(keys []string) {
	if len(keys) == 0 {
		fmt.Println("No keys found")
		return
	}
	fmt.Println("Keys")
	for _, key := range keys {
		fmt.Printf("  %s\n", key)
	}
}
