package roles

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/api"
	"github.com/stephnangue/warden/cmd/helpers"
)

var (
	createFlags roleFlags
	createJSON  string

	CreateCmd = &cobra.Command{
		Use:           "create <name>",
		SilenceUsage:  true,
		SilenceErrors: true,
		Short:         "Create a role in the current namespace (sudo)",
		Long: `
Usage: warden role create <name> [options]

  Create a role. A role names what a caller running under it may do
  (policies, cred_spec_name) and how discovery describes it to agents
  (description, skill, provider_path). Requires a token with sudo on
  sys/roles.

  A policy or credential spec that does not exist yet is accepted; the
  server answers with a warning on stderr. The "root" policy is refused.

  Two input modes (mutually exclusive):

    Full JSON payload (agent-friendly):

      $ warden role create deploy -json '{
          "description": "Deploys from acme CI",
          "policies": ["deploy"],
          "cred_spec_name": "deploy-role",
          "skill": "aws",
          "provider_path": "aws/",
          "metadata": {
            "team": "platform"
          }
        }'

      $ warden role create deploy -json @deploy-role.json
      $ cat deploy-role.json | warden role create deploy -json -

    Typed flags (human-friendly):

      $ warden role create deploy \
          -description="Deploys from acme CI" \
          -policies=deploy \
          -cred-spec-name=deploy-role \
          -provider-path=aws/

  Combine with -dry-run to validate the payload locally without creating
  the role.
`,
		Args: cobra.ExactArgs(1),
		RunE: runCreate,
	}
)

func init() {
	createFlags.bind(CreateCmd)
	CreateCmd.Flags().StringVarP(&createJSON, "json", "j", "",
		"Full JSON payload — '<json>', '@file.json', or '-' for stdin (mutually exclusive with the typed flags)")
}

func runCreate(cmd *cobra.Command, args []string) error {
	name := args[0]
	if err := validateRoleName(name); err != nil {
		return err
	}

	payload, err := helpers.ResolveJSONInput(createJSON)
	if err != nil {
		return err
	}
	if payload != nil {
		if err := helpers.RejectFlagsWithJSON(true, createFlags.changed(cmd)); err != nil {
			return err
		}
	} else {
		payload = createFlags.payload(cmd)
	}

	c, err := helpers.Client()
	if err != nil {
		return err
	}
	if helpers.ResolveDryRun() {
		return helpers.DryRun(c, "POST", "sys/roles/{name}", payload)
	}

	resource, err := c.Operator().Post("sys/roles/"+name, payload)
	if err != nil {
		return fmt.Errorf("error creating role %q: %w", name, err)
	}
	return renderRoleWrite(resource, name, "created")
}

// renderRoleWrite prints the role a create or update returned, with its
// warnings on stderr. marker ("created" or "updated") is set true in the
// rendered envelope.
func renderRoleWrite(resource *api.Resource, name, marker string) error {
	out := map[string]any{}
	var resData map[string]any
	if resource != nil {
		resData = resource.Data
	}
	helpers.MergeServerResponseInto(out, resData, map[string]any{
		"name": name,
		marker: true,
	})
	helpers.PrintWarnings(helpers.WarningsFromData(resData))
	return helpers.RenderMap(out, func() {
		printRoleTable(out)
	})
}
