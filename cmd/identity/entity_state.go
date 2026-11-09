package identity

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/cmd/helpers"
)

var (
	entityStateExpectedHash string

	EntityStateCmd = &cobra.Command{
		Use:           "state <entity> <active|suspended|retired>",
		SilenceUsage:  true,
		SilenceErrors: true,
		Short:         "Change the lifecycle state of an entity (sudo)",
		Long: `
Usage: warden identity entity state <entity> <active|suspended|retired> [options]

  Move an entity to a lifecycle state: active, suspended (reversible) or
  retired (final; the record becomes read-only and keeps its native
  identities claimed). Requires a token with sudo on sys/identity/entity.

  -expected-hash applies the change only if nobody changed the entity
  since you read it.

      $ warden identity entity state billing-agent suspended
      $ warden identity entity state billing-agent active
      $ warden identity entity state old-batch-agent retired
`,
		Args: cobra.ExactArgs(2),
		RunE: runEntityState,
	}
)

func init() {
	EntityStateCmd.Flags().StringVar(&entityStateExpectedHash, "expected-hash", "",
		"Change the state only if the entity still has this hash (from 'warden identity entity read')")
}

func runEntityState(cmd *cobra.Command, args []string) error {
	name, state := args[0], args[1]
	if err := validateEntityName(name); err != nil {
		return err
	}
	switch state {
	case "active", "suspended", "retired":
	default:
		return fmt.Errorf("state must be active, suspended or retired, got %q: %w", state, helpers.ErrUsage)
	}
	payload := map[string]any{"state": state}
	if entityStateExpectedHash != "" {
		payload["expected_hash"] = entityStateExpectedHash
	}

	c, err := helpers.Client()
	if err != nil {
		return err
	}
	if helpers.ResolveDryRun() {
		return helpers.DryRun(c, "POST", "sys/identity/entity/{entity}/state", payload)
	}
	resource, err := c.Operator().Post("sys/identity/entity/"+name+"/state", payload)
	if err != nil {
		return fmt.Errorf("error changing the state of entity %q: %w", name, err)
	}
	return renderEntityWrite(resource, name, "updated")
}
