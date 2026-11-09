package source

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/cmd/helpers"
)

var (
	keylessPlanNewName    string
	keylessPlanInputs     map[string]string
	keylessPlanSpecInputs map[string]string
	keylessPlanJSON       string

	KeylessPlanCmd = &cobra.Command{
		Use:   "keyless-plan <name>",
		Short: "Show how to replace a keyed credential source with a keyless one",
		Long: `
Usage: warden cred source keyless-plan <name> [flags]

  Plan the keyless replacement of a credential source that stores a secret,
  and of every spec bound to it. Nothing is written: the plan prints the
  upstream trust to configure, the keyless source and specs to create next to
  the keyed ones, and the keyed objects and upstream credentials to delete
  once roles use the new specs. Until then the keyed objects keep working, so
  there is nothing to roll back.

      $ warden cred source keyless-plan aws-prod

  A plan that needs more from you lists it under Blockers. Pass inputs for the
  source with -input and for a bound spec with -spec-input <spec>/<key>=<value>
  (its "name" key names the keyless spec):

      $ warden cred source keyless-plan vault-prod \
          -input=jwt_role=warden \
          -input=audience=vault \
          -spec-input=app-db/name=app-db-wif

  Or pass the whole request as JSON:

      $ warden cred source keyless-plan vault-prod -json '{
          "new_name": "vault-wif",
          "target": {
            "jwt_role": "warden",
            "audience": "vault"
          },
          "specs": {
            "app-db": {
              "name": "app-db-wif"
            }
          }
        }'

  Secret fields are refused as inputs: a keyless object never needs one.
`,
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.ExactArgs(1),
		RunE:          runKeylessPlan,
	}
)

func init() {
	KeylessPlanCmd.Flags().StringVar(&keylessPlanNewName, "new-name", "", "Name for the keyless source (default <name>-keyless)")
	KeylessPlanCmd.Flags().StringToStringVar(&keylessPlanInputs, "input", nil, "Input for the keyless source (key=value)")
	KeylessPlanCmd.Flags().StringToStringVar(&keylessPlanSpecInputs, "spec-input", nil, "Input for a bound spec (<spec>/<key>=value)")
	KeylessPlanCmd.Flags().StringVarP(&keylessPlanJSON, "json", "j", "", "Full JSON request — '<json>', '@file.json', or '-' for stdin (mutually exclusive with -new-name/-input/-spec-input)")
}

func runKeylessPlan(cmd *cobra.Command, args []string) error {
	name := args[0]
	if err := helpers.ValidatePath(name); err != nil {
		return err
	}

	c, err := helpers.Client()
	if err != nil {
		return err
	}

	input, err := helpers.KeylessPlanInput(keylessPlanJSON, keylessPlanNewName, keylessPlanInputs, keylessPlanSpecInputs)
	if err != nil {
		return err
	}

	plan, err := c.Sys().PlanKeylessCredentialSource(name, input)
	if err != nil {
		return fmt.Errorf("error planning keyless credential source: %w", err)
	}
	return helpers.RenderKeylessPlan("source", name, plan)
}
