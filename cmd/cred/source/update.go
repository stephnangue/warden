package source

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/api"
	"github.com/stephnangue/warden/cmd/helpers"
)

var (
	updateConfig map[string]string

	UpdateCmd = &cobra.Command{
		Use:           "update <name>",
		Short:         "Update a credential source",
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.ExactArgs(1),
		RunE:          runUpdate,
	}
)

func init() {
	UpdateCmd.Flags().StringToStringVar(&updateConfig, "config", nil, "Source configuration (key=value)")
	UpdateCmd.MarkFlagRequired("config")
}

func runUpdate(cmd *cobra.Command, args []string) error {
	name := args[0]
	if err := helpers.ValidatePath(name); err != nil {
		return err
	}

	c, err := helpers.Client()
	if err != nil {
		return err
	}

	resolvedConfig, err := helpers.ResolveFileRefs(updateConfig)
	if err != nil {
		return err
	}

	input := &api.UpdateCredentialSourceInput{
		Config: resolvedConfig,
	}

	output, err := c.Sys().UpdateCredentialSource(name, input)
	if err != nil {
		return fmt.Errorf("error updating credential source: %w", err)
	}

	return helpers.RenderMap(map[string]any{"name": output.Name, "updated": true}, func() {
		fmt.Printf("Success! Updated credential source: %s\n", output.Name)
	})
}
