package dev

import (
	"fmt"
	"strconv"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/cmd/helpers"
)

const devAuditPath = "sys/dev/audit"

var (
	auditN         int
	auditPrincipal string
	auditUser      string
	auditRole      string
	auditDecision  string

	AuditCmd = &cobra.Command{
		Use:           "audit",
		SilenceUsage:  true,
		SilenceErrors: true,
		Short:         "Show what the playground's audit log recorded",
		Long: `
Usage: warden dev audit [options]

  Show the newest entries of the playground's audit log: for each call, the
  agent and its role, the person it acted for, the tool, and what Warden
  decided and why. Tokens are never in the log in the clear.

      $ warden dev audit -limit 10
      $ warden dev audit -user alice
      $ warden dev audit -decision deny -limit 1

  With -o json, each entry also carries the raw audit record.
`,
		Args: cobra.NoArgs,
		RunE: runAudit,
	}
)

func init() {
	AuditCmd.Flags().IntVar(&auditN, "limit", 20, "How many entries, newest first")
	AuditCmd.Flags().StringVar(&auditPrincipal, "principal", "", "Only calls made by this agent")
	AuditCmd.Flags().StringVar(&auditUser, "user", "", "Only calls made for this user")
	AuditCmd.Flags().StringVar(&auditRole, "role", "", "Only calls made under this role")
	AuditCmd.Flags().StringVar(&auditDecision, "decision", "", `Only "allow" or "deny"`)
}

func runAudit(cmd *cobra.Command, args []string) error {
	query := map[string][]string{"n": {strconv.Itoa(auditN)}}
	for key, value := range map[string]string{
		"principal": auditPrincipal, "user": auditUser, "role": auditRole, "decision": auditDecision,
	} {
		if value != "" {
			query[key] = []string{value}
		}
	}

	c, err := helpers.Client()
	if err != nil {
		return err
	}
	resource, err := c.Operator().ReadWithData(devAuditPath, query)
	if err != nil {
		return fmt.Errorf("error reading the playground audit log: %w", err)
	}
	if resource == nil || resource.Data == nil {
		return fmt.Errorf("no audit log: is the server running with -dev-playground?")
	}

	raw, _ := resource.Data["entries"].([]any)
	items := make([]map[string]any, 0, len(raw))
	for _, e := range raw {
		if m, ok := e.(map[string]any); ok {
			items = append(items, m)
		}
	}
	return helpers.RenderList(items, func() {
		if len(items) == 0 {
			fmt.Println("No matching entries yet.")
			return
		}
		headers := []string{"Time", "Decision", "Role", "Agent", "User", "Tool", "Path", "Reason"}
		data := make([][]any, 0, len(items))
		for _, m := range items {
			data = append(data, []any{m["time"], m["decision"], m["role"], m["agent"], m["user"], m["tool"], m["path"], m["reason"]})
		}
		helpers.PrintTable(headers, data)
	})
}
