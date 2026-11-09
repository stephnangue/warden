package roles

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/mattn/go-isatty"
	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/cmd/helpers"
)

var (
	deleteForce        bool
	deleteExpectedHash string

	DeleteCmd = &cobra.Command{
		Use:           "delete <name>",
		SilenceUsage:  true,
		SilenceErrors: true,
		Short:         "Delete a role from the current namespace (sudo)",
		Long: `
Usage: warden role delete <name> [options]

  Delete a role. Requires a token with sudo on sys/roles.

  On a TTY without -force the command asks for confirmation; in scripts
  (stdin not a TTY) it does not, so pass -force to make the intent
  explicit. -expected-hash deletes the role only if nobody changed it
  since you read it.

  Examples:

      $ warden role delete deploy
      $ warden role delete deploy -force
      $ warden role delete deploy -force -expected-hash "$(warden role read deploy -o json | jq -r .hash)"
`,
		Args: cobra.ExactArgs(1),
		RunE: runDelete,
	}
)

func init() {
	DeleteCmd.Flags().BoolVarP(&deleteForce, "force", "f", false, "Skip the confirmation prompt")
	DeleteCmd.Flags().StringVar(&deleteExpectedHash, "expected-hash", "",
		"Delete only if the role still has this hash (from 'warden role read')")
}

func runDelete(cmd *cobra.Command, args []string) error {
	name := args[0]
	if err := validateRoleName(name); err != nil {
		return err
	}

	c, err := helpers.Client()
	if err != nil {
		return err
	}
	if helpers.ResolveDryRun() {
		return helpers.DryRun(c, "DELETE", "sys/roles/{name}", nil)
	}

	if !deleteForce && isatty.IsTerminal(os.Stdin.Fd()) {
		fmt.Fprintf(os.Stderr, "Delete role %q? This cannot be undone. (y/N) ", name)
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		if s := strings.ToLower(strings.TrimSpace(line)); s != "y" && s != "yes" {
			fmt.Fprintln(os.Stderr, "Aborted.")
			return nil
		}
	}

	warnings, err := c.Sys().DeleteRole(name, deleteExpectedHash)
	if err != nil {
		return fmt.Errorf("error deleting role %q: %w", name, err)
	}
	// Groups still listing the role are named on stderr, keeping stdout clean.
	helpers.PrintWarnings(warnings)
	out := map[string]any{
		"name":    name,
		"deleted": true,
	}
	if len(warnings) > 0 {
		out["warnings"] = warnings
	}
	return helpers.RenderMap(out, func() {
		fmt.Printf("Success! Deleted role: %s\n", name)
	})
}
