package identity

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/cmd/helpers"
)

var (
	entityCreateFlags entityFlags
	entityCreateJSON  string

	EntityCreateCmd = &cobra.Command{
		Use:           "create <name>",
		SilenceUsage:  true,
		SilenceErrors: true,
		Short:         "Create an entity in the current namespace (sudo)",
		Long: `
Usage: warden identity entity create <name> [options]

  Create an entity: an agent of record and the native identities it
  presents through auth mounts. "kind" is "agent" (the default; the only
  kind yet) and never changes. An entity is created active and without a
  sponsor: propose one afterwards ('warden identity entity sponsor
  propose'). Requires a token with sudo on sys/identity/entity.

  "governed_by" is derived, never written: "warden" once the entity has an
  accepted sponsor and a description, empty before ('warden identity
  entity list -ungoverned' lists those).

  "aliases" claims native identities, each as the auth mount derives it
  from a credential (its alias_name_source) through the mount by path. A
  native identity is claimed by one entity in a namespace; one another
  entity claims is refused ('warden identity alias move' takes it). A mount
  admitting humans cannot be claimed by an agent.

  Two input modes (mutually exclusive):

    Full JSON payload (agent-friendly):

      $ warden identity entity create billing-agent -json '{
          "kind": "agent",
          "description": "Reconciles supplier invoices against purchase orders",
          "profile": {
            "purpose": "billing",
            "runtime": "langgraph",
            "publisher": "corp-finance-eng"
          },
          "metadata": {
            "team": "billing"
          },
          "aliases": [
            { "mount": "auth/kubernetes/", "name": "system:serviceaccount:billing:agent" },
            { "mount": "auth/spiffe/",     "name": "spiffe://corp.example/ns/billing/sa/agent" }
          ]
        }'

      $ warden identity entity create billing-agent -json @billing-agent.json

    Typed flags (human-friendly), one -alias per native identity:

      $ warden identity entity create billing-agent \
          -description="Reconciles supplier invoices" \
          -profile=runtime=langgraph \
          -alias=auth/kubernetes/=system:serviceaccount:billing:agent

  Combine with -dry-run to validate the payload locally without creating
  the entity.
`,
		Args: cobra.ExactArgs(1),
		RunE: runEntityCreate,
	}
)

func init() {
	entityCreateFlags.bind(EntityCreateCmd, true)
	EntityCreateCmd.Flags().StringVarP(&entityCreateJSON, "json", "j", "",
		"Full JSON payload — '<json>', '@file.json', or '-' for stdin (mutually exclusive with the typed flags)")
}

func runEntityCreate(cmd *cobra.Command, args []string) error {
	name := args[0]
	if err := validateEntityName(name); err != nil {
		return err
	}

	payload, err := helpers.ResolveJSONInput(entityCreateJSON)
	if err != nil {
		return err
	}
	if payload != nil {
		if err := helpers.RejectFlagsWithJSON(true, entityCreateFlags.changed(cmd)); err != nil {
			return err
		}
	} else if payload, err = entityCreateFlags.payload(cmd); err != nil {
		return err
	}

	c, err := helpers.Client()
	if err != nil {
		return err
	}
	if helpers.ResolveDryRun() {
		return helpers.DryRun(c, "POST", "sys/identity/entity/{name}", payload)
	}

	resource, err := c.Operator().Post("sys/identity/entity/"+name, payload)
	if err != nil {
		return fmt.Errorf("error creating entity %q: %w", name, err)
	}
	return renderEntityWrite(resource, name, "created")
}
