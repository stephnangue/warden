package skills

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/cmd/helpers"
)

var (
	updateDescription string
	updateCategory    string
	updateRequires    []string
	updateUpstream    string
	updateProvider    string
	updateBodyFile    string
	updateJSON        string

	UpdateCmd = &cobra.Command{
		Use:           "update NAME",
		SilenceUsage:  true,
		SilenceErrors: true,
		Short:         "Update an existing skill (root namespace only)",
		Long: `
Usage: warden skill update NAME [options]

  Update an existing skill. Update is field-by-field merge: only the
  fields you pass overwrite the stored record. CreatedAt, Origin, Name,
  and Version are managed by the server and cannot be patched.

  Mutations require a root namespace token; sub-namespace tokens get 403.

  Two input modes (mutually exclusive):

    Typed flags (human-friendly):

      $ warden skill update aws --description="our local override"

    Full JSON payload (agent-friendly):

      $ warden skill update aws --json @patch.json
      $ cat patch.json | warden skill update aws --json -

  --json is mutually exclusive with the typed --description / --category
  / --requires / --upstream / --provider / --body-file flags.

  To update the body, point --body-file at a markdown file on disk;
  the file's content is sent as the new body verbatim.

  Empty values are treated as "don't change" — to clear an optional
  field (e.g. requires, upstream) use --json with the explicit empty
  value, e.g. --json '{"requires":[]}'.
`,
		Args: cobra.ExactArgs(1),
		RunE: runUpdate,
	}
)

func init() {
	UpdateCmd.Flags().StringVar(&updateDescription, "description", "",
		"Replace the description")
	UpdateCmd.Flags().StringVar(&updateCategory, "category", "",
		"Replace the category (agent-flow|shared|provider-guide|troubleshooting|custom)")
	UpdateCmd.Flags().StringSliceVar(&updateRequires, "requires", nil,
		"Replace the requires list (repeat or comma-separated)")
	UpdateCmd.Flags().StringVar(&updateUpstream, "upstream", "",
		"Replace the upstream reference")
	UpdateCmd.Flags().StringVar(&updateProvider, "provider", "",
		"Replace the provider type (relevant for provider-guide category)")
	UpdateCmd.Flags().StringVar(&updateBodyFile, "body-file", "",
		"Replace the body with the contents of a markdown file")
	UpdateCmd.Flags().StringVarP(&updateJSON, "json", "j", "",
		"Full JSON payload — '<json>', '@file.json', or '-' for stdin")
}

func runUpdate(cmd *cobra.Command, args []string) error {
	c, err := helpers.Client()
	if err != nil {
		return err
	}
	name := args[0]

	jsonPayload, err := helpers.ResolveJSONInput(updateJSON)
	if err != nil {
		return err
	}

	var payload map[string]any
	if jsonPayload != nil {
		if err := helpers.RejectFlagsWithJSON(true, map[string]bool{
			"--description": updateDescription != "",
			"--category":    updateCategory != "",
			"--requires":    len(updateRequires) > 0,
			"--upstream":    updateUpstream != "",
			"--provider":    updateProvider != "",
			"--body-file":   updateBodyFile != "",
		}); err != nil {
			return err
		}
		payload = jsonPayload
	} else {
		// Typed mode — build a patch out of whichever flags were set.
		payload = map[string]any{}
		if updateDescription != "" {
			payload["description"] = updateDescription
		}
		if updateCategory != "" {
			payload["category"] = updateCategory
		}
		if len(updateRequires) > 0 {
			payload["requires"] = updateRequires
		}
		if updateUpstream != "" {
			payload["upstream"] = updateUpstream
		}
		if updateProvider != "" {
			payload["provider"] = updateProvider
		}
		if updateBodyFile != "" {
			bodyBytes, err := os.ReadFile(updateBodyFile)
			if err != nil {
				return fmt.Errorf("--body-file %s: %w", updateBodyFile, err)
			}
			payload["body"] = string(bodyBytes)
		}
		if len(payload) == 0 {
			return fmt.Errorf("no fields to update: pass at least one flag or use --json: %w", helpers.ErrUsage)
		}
	}

	if helpers.ResolveDryRun() {
		return helpers.DryRun(c, "PUT", "sys/skills/{name}", payload)
	}

	resource, err := c.Operator().Write("sys/skills/"+name, payload)
	if err != nil {
		return fmt.Errorf("error updating skill: %w", err)
	}
	out := map[string]any{}
	var resData map[string]any
	if resource != nil {
		resData = resource.Data
	}
	helpers.MergeServerResponseInto(out, resData, map[string]any{
		"name":    name,
		"updated": true,
	})
	return helpers.RenderMap(out, func() {
		fmt.Printf("Success! Updated skill: %s\n", name)
	})
}
