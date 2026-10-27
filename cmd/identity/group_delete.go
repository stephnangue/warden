package identity

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
	deleteType         string

	GroupDeleteCmd = &cobra.Command{
		Use:           "delete <name>",
		SilenceUsage:  true,
		SilenceErrors: true,
		Short:         "Delete a group from the current namespace (sudo)",
		Long: `
Usage: warden identity group delete <name> [options]

  Delete a group. Its members lose the roles it granted on their next
  request, unless another group grants them too. Requires a token with
  sudo on sys/identity/group.

  On a TTY without -force the command asks for confirmation; in scripts
  (stdin not a TTY) it does not, so pass -force to make the intent
  explicit. -expected-hash deletes the group only if nobody changed it
  since you read it.

  The server requires the group's type on every write. Without -type the
  command reads the group to learn it; pass -type when your policy only
  lets you write (and read) groups of one type.

  Examples:

      $ warden identity group delete ci-deployers
      $ warden identity group delete ci-deployers -type virtual -force
      $ warden identity group delete ci-deployers -force \
          -expected-hash "$(warden identity group read ci-deployers -o json | jq -r .hash)"
`,
		Args: cobra.ExactArgs(1),
		RunE: runGroupDelete,
	}
)

func init() {
	GroupDeleteCmd.Flags().BoolVarP(&deleteForce, "force", "f", false, "Skip the confirmation prompt")
	GroupDeleteCmd.Flags().StringVar(&deleteExpectedHash, "expected-hash", "",
		"Delete only if the group still has this hash (from 'warden identity group read')")
	GroupDeleteCmd.Flags().StringVar(&deleteType, "type", "",
		"The group's type; read from the server when omitted")
}

func runGroupDelete(cmd *cobra.Command, args []string) error {
	name := args[0]
	if err := validateGroupName(name); err != nil {
		return err
	}

	c, err := helpers.Client()
	if err != nil {
		return err
	}
	if helpers.ResolveDryRun() {
		return helpers.DryRun(c, "DELETE", "sys/identity/group/{name}", nil)
	}
	groupType, err := resolveGroupType(c, name, deleteType)
	if err != nil {
		return err
	}

	if !deleteForce && isatty.IsTerminal(os.Stdin.Fd()) {
		fmt.Fprintf(os.Stderr, "Delete group %q? Its members lose the roles it grants. (y/N) ", name)
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		if s := strings.ToLower(strings.TrimSpace(line)); s != "y" && s != "yes" {
			fmt.Fprintln(os.Stderr, "Aborted.")
			return nil
		}
	}

	if err := c.Sys().DeleteGroup(name, groupType, deleteExpectedHash); err != nil {
		return fmt.Errorf("error deleting group %q: %w", name, err)
	}
	return helpers.RenderMap(map[string]any{
		"name":    name,
		"deleted": true,
	}, func() {
		fmt.Printf("Success! Deleted group: %s\n", name)
	})
}
