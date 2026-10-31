package roles

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/api"
	"github.com/stephnangue/warden/cmd/helpers"
)

var UseCmd = &cobra.Command{
	Use:           "use [name]",
	SilenceUsage:  true,
	SilenceErrors: true,
	Short:         "Choose the role warden commands run under in the current session",
	Long: `
Usage: warden role use [name]

  Sets the role the commands of your warden login session run under. With a
  name, checks that you can assume it and uses it; without one, lists the
  roles you can assume and lets you pick one (arrows to move, type to filter,
  Enter to select, Esc to keep the current one).

  The role is saved in the session; no new login is needed. -role and
  WARDEN_ROLE still override it for one command.

  Examples:

      $ warden role use
      $ warden role use auditor
`,
	Args: cobra.MaximumNArgs(1),
	RunE: runUse,
}

func runUse(cmd *cobra.Command, args []string) error {
	if api.ReadWardenVariable(api.EnvWardenToken) != "" {
		return fmt.Errorf("warden role use sets the role of a warden login session; with WARDEN_TOKEN set, use -role or WARDEN_ROLE: %w", helpers.ErrUsage)
	}
	c, s, err := helpers.RequireSession()
	if err != nil {
		return err
	}
	name := ""
	if len(args) == 1 {
		name = args[0]
	}
	role, err := ChooseRole(c, name)
	if err != nil {
		return err
	}
	if role == "" {
		return nil
	}
	s.Role = role
	if err := helpers.SaveSession(s); err != nil {
		return err
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "Using role %q for warden commands (namespace %s).\n", role, helpers.DisplayNamespace(s.Namespace))
	return nil
}

// ChooseRole returns the role a session is to run under, among the roles the
// session's identity can assume (sys/introspect/roles): requested when it is
// one of them, else the only one, else the one picked on the terminal. It
// returns "" with nothing chosen: no role is granted (a warning says so),
// several are and there is no terminal (they are listed on stderr), or the
// picker was skipped. A requested role that is not granted is an error.
func ChooseRole(c *api.Client, requested string) (string, error) {
	// Discovery takes no role: never send one.
	c.ClearRole()
	resource, err := c.Operator().ReadWithData("sys/introspect/roles", nil)
	if err != nil {
		return "", fmt.Errorf("failed to list the roles you can assume: %w", err)
	}
	var raw []any
	if resource != nil && resource.Data != nil {
		raw, _ = resource.Data["roles"].([]any)
	}
	items := projectRoles(raw)
	names := make([]string, len(items))
	for i, it := range items {
		names[i], _ = it["name"].(string)
	}

	switch {
	case requested != "":
		for _, n := range names {
			if n == requested {
				return requested, nil
			}
		}
		if len(names) == 0 {
			return "", fmt.Errorf("role %q is not one you can assume here: no group grants you a role in this namespace: %w", requested, helpers.ErrUsage)
		}
		return "", fmt.Errorf("role %q is not one you can assume here (you can assume: %s): %w", requested, strings.Join(names, ", "), helpers.ErrUsage)
	case len(items) == 0:
		helpers.PrintWarnings([]string{"no group grants you a role in this namespace"})
		return "", nil
	case len(items) == 1:
		return names[0], nil
	}

	choices := make([]helpers.PickItem, len(items))
	for i, it := range items {
		choices[i] = helpers.PickItem{Name: names[i]}
		choices[i].Description, _ = it["description"].(string)
		choices[i].Detail, _ = it["provider_path"].(string)
	}
	if !helpers.Interactive() {
		helpers.PrintWarnings([]string{"several roles can be assumed; choose one with warden role use <name>, or -role"})
		helpers.PrintChoices(choices)
		return "", nil
	}
	idx, err := helpers.Pick("Choose a role (↑/↓ to move, type to filter, Enter to select, Esc to skip):", choices)
	switch {
	case errors.Is(err, helpers.ErrPickSkipped):
		return "", nil
	case err != nil:
		return "", err
	}
	return names[idx], nil
}
