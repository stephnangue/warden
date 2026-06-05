package providers

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/cmd/helpers"
)

var (
	tuneDescription string
	tunePath        string
	tuneJSON        string

	TuneCmd = &cobra.Command{
		Use:           "tune [PATH]",
		Args:          cobra.MaximumNArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		Short:         "Update a provider's description",
		Long: `
Usage: warden provider tune [options] [PATH]

  Update the description of a provider enabled at PATH. The PATH may be
  supplied either positionally or via -path (pick one — combining both is
  rejected). Two input modes:

    Typed flag (human-friendly):

      $ warden provider tune aws/ -description="Production AWS"

    Full JSON payload (agent-friendly):

      $ warden provider tune aws/ -json @tune.json
      $ echo '{"description":"Production AWS"}' | warden provider tune aws/ -json -

  Tuning is a partial update: omitting -description leaves the current
  description unchanged, while -description="" clears it. -json is mutually
  exclusive with -description. Combine with -dry-run to preview the request
  without applying it.
`,
		RunE: runTune,
	}
)

func init() {
	TuneCmd.Flags().StringVar(&tuneDescription, "description", "", "New description for the provider")
	TuneCmd.Flags().StringVar(&tunePath, "path", "", "Mount path (alternative to the positional PATH argument)")
	TuneCmd.Flags().StringVarP(&tuneJSON, "json", "j", "", "Full JSON payload — '<json>', '@file.json', or '-' for stdin (mutually exclusive with -description)")
}

func runTune(cmd *cobra.Command, args []string) error {
	path, err := helpers.RequirePath(args, tunePath)
	if err != nil {
		return err
	}
	if !strings.HasSuffix(path, "/") {
		path = path + "/"
	}
	if err := helpers.ValidatePath(path); err != nil {
		return err
	}

	c, err := helpers.Client()
	if err != nil {
		return err
	}

	jsonPayload, err := helpers.ResolveJSONInput(tuneJSON)
	if err != nil {
		return err
	}

	if jsonPayload != nil {
		if err := helpers.RejectFlagsWithJSON(true, map[string]bool{
			"-description": cmd.Flags().Changed("description"),
		}); err != nil {
			return err
		}
		if helpers.ResolveDryRun() {
			return helpers.DryRun(c, "POST", "sys/providers/{path}/tune", jsonPayload)
		}
		resource, err := c.Operator().Post("sys/providers/"+path+"tune", jsonPayload)
		if err != nil {
			return fmt.Errorf("error tuning provider: %w", err)
		}
		data := map[string]any{}
		var resData map[string]any
		if resource != nil {
			resData = resource.Data
		}
		helpers.MergeServerResponseInto(data, resData, map[string]any{
			"path":  path,
			"tuned": true,
		})
		return helpers.RenderMap(data, func() {
			fmt.Printf("Success! Tuned provider at: %s\n", path)
		})
	}

	// Typed-flag mode. Send "description" only when the operator actually set
	// the flag, so a bare `tune` is a no-op rather than clearing the field.
	data := map[string]any{}
	if cmd.Flags().Changed("description") {
		data["description"] = tuneDescription
	}

	if helpers.ResolveDryRun() {
		return helpers.DryRun(c, "POST", "sys/providers/{path}/tune", data)
	}

	if err := c.Sys().TuneMount(path, data); err != nil {
		return fmt.Errorf("error tuning provider: %w", err)
	}

	return helpers.RenderMap(map[string]any{"path": path, "tuned": true}, func() {
		fmt.Printf("Success! Tuned provider at: %s\n", path)
	})
}
