package identity

import (
	"bufio"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/mattn/go-isatty"
	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/api"
	"github.com/stephnangue/warden/cmd/helpers"
)

var (
	entityDeleteForce        bool
	entityDeleteRetired      bool
	entityDeleteExpectedHash string

	EntityDeleteCmd = &cobra.Command{
		Use:           "delete <name>",
		SilenceUsage:  true,
		SilenceErrors: true,
		Short:         "Delete an entity from the current namespace (sudo)",
		Long: `
Usage: warden identity entity delete <name> [options]

  Delete an entity. The native identities it claims are released: they
  are unclaimed again. Requires a token with sudo on sys/identity/entity.

  A retired entity keeps its native identities claimed, so that no other
  entity takes them unnoticed; deleting it is refused unless you pass
  -retired, which releases them. To keep them claimed elsewhere, move them
  first ('warden identity alias move').

  On a TTY without -force the command asks for confirmation; in scripts
  (stdin not a TTY) it does not, so pass -force to make the intent
  explicit. -expected-hash deletes the entity only if nobody changed it
  since you read it.

  Examples:

      $ warden identity entity delete ci-runner
      $ warden identity entity delete ci-runner -force
      $ warden identity entity delete old-batch-agent -retired -force
`,
		Args: cobra.ExactArgs(1),
		RunE: runEntityDelete,
	}
)

func init() {
	EntityDeleteCmd.Flags().BoolVarP(&entityDeleteForce, "force", "f", false, "Skip the confirmation prompt")
	EntityDeleteCmd.Flags().BoolVar(&entityDeleteRetired, "retired", false,
		"Delete a retired entity, releasing the native identities it keeps claimed")
	EntityDeleteCmd.Flags().StringVar(&entityDeleteExpectedHash, "expected-hash", "",
		"Delete only if the entity still has this hash (from 'warden identity entity read')")
}

func runEntityDelete(cmd *cobra.Command, args []string) error {
	name := args[0]
	if err := validateEntityName(name); err != nil {
		return err
	}

	c, err := helpers.Client()
	if err != nil {
		return err
	}
	if helpers.ResolveDryRun() {
		return helpers.DryRun(c, "DELETE", "sys/identity/entity/{name}", nil)
	}

	if !entityDeleteForce && isatty.IsTerminal(os.Stdin.Fd()) {
		fmt.Fprintf(os.Stderr, "Delete entity %q? The native identities it claims are unclaimed again. (y/N) ", name)
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		if s := strings.ToLower(strings.TrimSpace(line)); s != "y" && s != "yes" {
			fmt.Fprintln(os.Stderr, "Aborted.")
			return nil
		}
	}

	warnings, err := c.Sys().DeleteEntity(name, entityDeleteExpectedHash, entityDeleteRetired)
	if err != nil {
		// The server asks for force, which this command sends as -retired;
		// -force only skips the prompt.
		var re *api.ResponseError
		if !entityDeleteRetired && errors.As(err, &re) && re.StatusCode == http.StatusConflict &&
			strings.Contains(err.Error(), "is retired") {
			return helpers.WithHint(fmt.Errorf("error deleting entity %q: %w", name, err),
				"pass -retired to delete a retired entity; its native identities are unclaimed again")
		}
		return fmt.Errorf("error deleting entity %q: %w", name, err)
	}
	// A forced delete of a retired entity says so: to stderr, and in the
	// structured output.
	helpers.PrintWarnings(warnings)

	data := map[string]any{"name": name, "deleted": true}
	if len(warnings) > 0 {
		data["warnings"] = warnings
	}
	return helpers.RenderMap(data, func() {
		fmt.Printf("Success! Deleted entity: %s\n", name)
	})
}
