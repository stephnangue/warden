package skills

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
	deleteForce bool

	DeleteCmd = &cobra.Command{
		Use:           "delete NAME",
		SilenceUsage:  true,
		SilenceErrors: true,
		Short:         "Delete a skill from the global registry (root namespace only)",
		Long: `
Usage: warden skill delete NAME [options]

  Delete a skill. The seeded troubleshooting skill and seeded provider
  skills can be deleted — once removed, they stay removed across restarts
  (the seed marker is sticky). Run 'warden skill list' first if you're not
  sure of the exact name.

  Mutations require a root namespace token; sub-namespace tokens get 403.

  On a TTY without -force the command prompts for confirmation. In
  scripts or pipes (stdin not a TTY), confirmation is skipped because
  there is no one to answer the prompt — use -force in scripts to
  make the intent explicit.

  Examples:

    Interactive delete:

      $ warden skill delete my-runbook

    Scripted delete:

      $ warden skill delete my-runbook -force
`,
		Args: cobra.ExactArgs(1),
		RunE: runDelete,
	}
)

func init() {
	DeleteCmd.Flags().BoolVar(&deleteForce, "force", false,
		"Skip the interactive confirmation prompt")
}

func runDelete(cmd *cobra.Command, args []string) error {
	c, err := helpers.Client()
	if err != nil {
		return err
	}

	name := args[0]

	if !deleteForce && isatty.IsTerminal(os.Stdin.Fd()) {
		fmt.Fprintf(os.Stderr, "Delete skill %q? This cannot be undone. (y/N) ", name)
		reader := bufio.NewReader(os.Stdin)
		line, _ := reader.ReadString('\n')
		if !confirmed(line) {
			fmt.Fprintln(os.Stderr, "Aborted.")
			return nil
		}
	}

	if helpers.ResolveDryRun() {
		return helpers.DryRun(c, "DELETE", "sys/skills/{name}", nil)
	}

	if _, err := c.Operator().Delete("sys/skills/" + name); err != nil {
		return fmt.Errorf("error deleting skill %q: %w", name, err)
	}

	return helpers.RenderMap(map[string]any{
		"name":    name,
		"deleted": true,
	}, func() {
		fmt.Printf("Success! Deleted skill: %s\n", name)
	})
}

func confirmed(line string) bool {
	s := strings.ToLower(strings.TrimSpace(line))
	return s == "y" || s == "yes"
}
