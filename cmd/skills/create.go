package skills

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/cmd/helpers"
)

var (
	createName        string
	createDescription string
	createCategory    string
	createRequires    []string
	createUpstream    string
	createProvider    string
	createBodyFile    string
	createJSON        string

	CreateCmd = &cobra.Command{
		Use:           "create [NAME]",
		SilenceUsage:  true,
		SilenceErrors: true,
		Short:         "Create a new skill in the global registry (root namespace only)",
		Long: `
Usage: warden skill create [NAME] [options]

  Create a new skill. Mutations to /v1/sys/skills require a root
  namespace token; running this from a sub-namespace surfaces the
  server's 403 with a clear message.

  Two input modes (mutually exclusive):

    Typed flags (human-friendly):

      $ warden skill create --name=my-runbook --category=custom \
          --description="ops on-call" --body-file=./runbook.md

    Full JSON payload (agent-friendly):

      $ warden skill create my-runbook --json @skill.json
      $ cat skill.json | warden skill create my-runbook --json -

  --json is mutually exclusive with --name / --description / --category
  / --requires / --upstream / --provider / --body-file. The skill name
  is taken from the positional argument when given, otherwise from
  --name or the payload's "name" field.

  Required fields (typed or via payload): name, description, category,
  body. provider-guide skills also require a "provider" field.
`,
		RunE: runCreate,
	}
)

func init() {
	CreateCmd.Flags().StringVar(&createName, "name", "",
		"Skill name (unique slug, [a-z0-9_-]{2,64}); required unless --json supplies one")
	CreateCmd.Flags().StringVar(&createDescription, "description", "",
		"Human-readable one-line summary; required unless --json")
	CreateCmd.Flags().StringVar(&createCategory, "category", "",
		"agent-flow | shared | provider-guide | troubleshooting | custom")
	CreateCmd.Flags().StringSliceVar(&createRequires, "requires", nil,
		"Names of other skills this one depends on (repeat or comma-separated)")
	CreateCmd.Flags().StringVar(&createUpstream, "upstream", "",
		"Reference to an upstream system, when applicable")
	CreateCmd.Flags().StringVar(&createProvider, "provider", "",
		"Provider type this skill describes (required when category=provider-guide)")
	CreateCmd.Flags().StringVar(&createBodyFile, "body-file", "",
		"Path to the markdown body file")
	CreateCmd.Flags().StringVarP(&createJSON, "json", "j", "",
		"Full JSON payload — '<json>', '@file.json', or '-' for stdin")
}

func runCreate(cmd *cobra.Command, args []string) error {
	c, err := helpers.Client()
	if err != nil {
		return err
	}

	jsonPayload, err := helpers.ResolveJSONInput(createJSON)
	if err != nil {
		return err
	}

	if jsonPayload != nil {
		if err := helpers.RejectFlagsWithJSON(true, map[string]bool{
			"--name":        createName != "",
			"--description": createDescription != "",
			"--category":    createCategory != "",
			"--requires":    len(createRequires) > 0,
			"--upstream":    createUpstream != "",
			"--provider":    createProvider != "",
			"--body-file":   createBodyFile != "",
		}); err != nil {
			return err
		}
		name := skillNameFromArgOrPayload(args, jsonPayload)
		if name == "" {
			return fmt.Errorf("--json without a positional NAME and without a 'name' field in the payload: cannot determine skill name: %w", helpers.ErrUsage)
		}
		if helpers.ResolveDryRun() {
			return helpers.DryRun(c, "POST", "sys/skills/{name}", jsonPayload)
		}
		resource, err := c.Operator().Post("sys/skills/"+name, jsonPayload)
		if err != nil {
			return fmt.Errorf("error creating skill: %w", err)
		}
		out := map[string]any{}
		var resData map[string]any
		if resource != nil {
			resData = resource.Data
		}
		helpers.MergeServerResponseInto(out, resData, map[string]any{
			"name":    name,
			"created": true,
		})
		return helpers.RenderMap(out, func() {
			fmt.Printf("Success! Created skill: %s\n", name)
		})
	}

	// Typed mode.
	name := createName
	if len(args) > 0 {
		name = args[0]
	}
	if name == "" {
		return fmt.Errorf("either a positional NAME, --name, or --json is required: %w", helpers.ErrUsage)
	}
	if createDescription == "" {
		return fmt.Errorf("--description is required (or use --json): %w", helpers.ErrUsage)
	}
	if createCategory == "" {
		return fmt.Errorf("--category is required (or use --json): %w", helpers.ErrUsage)
	}
	if createBodyFile == "" {
		return fmt.Errorf("--body-file is required (or use --json): %w", helpers.ErrUsage)
	}
	bodyBytes, err := os.ReadFile(createBodyFile)
	if err != nil {
		return fmt.Errorf("--body-file %s: %w", createBodyFile, err)
	}

	payload := map[string]any{
		"name":        name,
		"description": createDescription,
		"category":    createCategory,
		"body":        string(bodyBytes),
	}
	if len(createRequires) > 0 {
		payload["requires"] = createRequires
	}
	if createUpstream != "" {
		payload["upstream"] = createUpstream
	}
	if createProvider != "" {
		payload["provider"] = createProvider
	}

	if helpers.ResolveDryRun() {
		return helpers.DryRun(c, "POST", "sys/skills/{name}", payload)
	}

	resource, err := c.Operator().Post("sys/skills/"+name, payload)
	if err != nil {
		return fmt.Errorf("error creating skill: %w", err)
	}
	out := map[string]any{}
	var resData map[string]any
	if resource != nil {
		resData = resource.Data
	}
	helpers.MergeServerResponseInto(out, resData, map[string]any{
		"name":    name,
		"created": true,
	})
	return helpers.RenderMap(out, func() {
		fmt.Printf("Success! Created skill: %s\n", name)
	})
}

// skillNameFromArgOrPayload mirrors helpers.MountPathFromArgOrPayload but
// reads the payload's "name" field instead of "type", and does not
// suffix with a trailing slash (skills are name-keyed, not path-keyed).
func skillNameFromArgOrPayload(args []string, payload map[string]any) string {
	if len(args) > 0 && args[0] != "" {
		return args[0]
	}
	if n, ok := payload["name"].(string); ok {
		return n
	}
	return ""
}
