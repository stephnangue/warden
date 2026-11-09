package spec

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/cmd/helpers"
)

var (
	keylessPlanNewName string
	keylessPlanInputs  map[string]string
	keylessPlanJSON    string

	KeylessPlanCmd = &cobra.Command{
		Use:   "keyless-plan <name>",
		Short: "Show how to replace a spec that stores a secret with a keyless one",
		Long: `
Usage: warden cred spec keyless-plan <name> [flags]

  Plan the keyless replacement of a credential spec that stores its own
  secret: a spec of the same type that fetches the secret per request through
  credential chaining (secret_spec). Nothing is written: the plan prints the
  spec to create next to the keyed one, and what to delete once roles use it.
  A spec whose secret comes from its source is planned with
  'warden cred source keyless-plan' instead.

      $ warden cred spec keyless-plan github-pat \
          -input=secret_spec=github-pat-from-vault

  Or pass the whole request as JSON:

      $ warden cred spec keyless-plan github-pat -json '{
          "new_name": "github-chained",
          "target": {
            "secret_spec": "github-pat-from-vault"
          }
        }'

  Secret fields are refused as inputs: a keyless spec never needs one.
`,
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.ExactArgs(1),
		RunE:          runKeylessPlan,
	}
)

func init() {
	KeylessPlanCmd.Flags().StringVar(&keylessPlanNewName, "new-name", "", "Name for the keyless spec (default <name>-keyless)")
	KeylessPlanCmd.Flags().StringToStringVar(&keylessPlanInputs, "input", nil, "Input for the keyless spec (key=value)")
	KeylessPlanCmd.Flags().StringVarP(&keylessPlanJSON, "json", "j", "", "Full JSON request — '<json>', '@file.json', or '-' for stdin (mutually exclusive with -new-name/-input)")
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

	input, err := helpers.KeylessPlanInput(keylessPlanJSON, keylessPlanNewName, keylessPlanInputs, nil)
	if err != nil {
		return err
	}

	plan, err := c.Sys().PlanKeylessCredentialSpec(name, input)
	if err != nil {
		return fmt.Errorf("error planning keyless credential spec: %w", err)
	}
	return helpers.RenderKeylessPlan("spec", name, plan)
}
