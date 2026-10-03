package dev

import (
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/cmd/helpers"
	"github.com/stephnangue/warden/internal/playground"
)

const devScenariosPath = "sys/dev/scenarios"

var ScenariosCmd = &cobra.Command{
	Use:           "scenarios [N]",
	SilenceUsage:  true,
	SilenceErrors: true,
	Short:         "Show the playground's scenarios, with what to do and what to look for",
	Long: `
Usage: warden dev scenarios [N]

  Show the playground's tour: one idea about how Warden works per scenario,
  the commands to run, what to ask your agent, and what to look for. The
  commands are built for this server's address.

  Every scenario attaches at most one bank to the agent's client. One that
  needs a different role or identity replaces the bank, then asks you to
  reconnect, since an MCP client caches a server's tools.

      $ warden dev scenarios
      $ warden dev scenarios 4
`,
	Args: cobra.MaximumNArgs(1),
	RunE: runScenarios,
}

type scenariosResponse struct {
	Setup     []string              `json:"setup"`
	Scenarios []playground.Scenario `json:"scenarios"`
}

func runScenarios(cmd *cobra.Command, args []string) error {
	only := 0
	if len(args) == 1 {
		n, err := strconv.Atoi(args[0])
		if err != nil || n < 1 {
			return fmt.Errorf("N must be a scenario number: %w", helpers.ErrUsage)
		}
		only = n
	}

	c, err := helpers.Client()
	if err != nil {
		return err
	}
	resource, err := c.Operator().Read(devScenariosPath)
	if err != nil {
		return fmt.Errorf("error reading the playground scenarios: %w", err)
	}
	if resource == nil || resource.Data == nil {
		return fmt.Errorf("no scenarios: is the server running with -dev-playground?")
	}
	var resp scenariosResponse
	raw, _ := json.Marshal(resource.Data)
	if err := json.Unmarshal(raw, &resp); err != nil {
		return fmt.Errorf("decode the scenarios: %w", err)
	}
	if only > len(resp.Scenarios) {
		return fmt.Errorf("there are %d scenarios: %w", len(resp.Scenarios), helpers.ErrUsage)
	}

	switch helpers.ResolveFormat() {
	case helpers.FormatJSON, helpers.FormatNDJSON:
		if only > 0 {
			raw, _ := json.Marshal(resp.Scenarios[only-1])
			var one map[string]any
			_ = json.Unmarshal(raw, &one)
			return helpers.RenderMap(one, nil)
		}
		return helpers.RenderMap(resource.Data, nil)
	}
	renderTour(cmd.OutOrStdout(), resp, only, c.Address())
	return nil
}

// renderTour prints the scenarios as a walkthrough. only selects one scenario;
// 0 prints them all, with the setup first.
func renderTour(w io.Writer, resp scenariosResponse, only int, wardenAddr string) {
	if only == 0 {
		fmt.Fprintln(w, "Setup, once:")
		fmt.Fprintln(w)
		fmt.Fprintf(w, "  export WARDEN_ADDR=%s\n", wardenAddr)
		for _, line := range resp.Setup {
			fmt.Fprintf(w, "  %s\n", line)
		}
		fmt.Fprintln(w)
	}
	for _, s := range resp.Scenarios {
		if only != 0 && s.Number != only {
			continue
		}
		fmt.Fprintf(w, "%d. %s\n\n", s.Number, s.Title)
		var cmds []string
		for _, server := range s.Detach {
			cmds = append(cmds, "claude mcp remove "+server)
		}
		if s.Attach != nil {
			// The bank is replaced, never added beside another one.
			if s.Attach.Server == "bank" && s.Number > 1 {
				cmds = append(cmds, "claude mcp remove bank")
			}
			cmds = append(cmds, playground.ClaudeAddCommand(s.Attach, wardenAddr))
		}
		cmds = append(cmds, s.Commands...)
		printCommands(w, cmds)
		if s.Attach != nil && s.Number > 1 || len(s.Detach) > 0 {
			printReconnectHint(w)
		}
		for _, ask := range s.Ask {
			fmt.Fprintf(w, "   Ask: %q\n", ask)
		}
		if len(s.Ask) > 0 {
			fmt.Fprintln(w)
		}
		fmt.Fprintln(w, "   What it shows:")
		for _, line := range s.Shows {
			fmt.Fprintf(w, "   - %s\n", line)
		}
		fmt.Fprintln(w)
		for _, v := range s.Variants {
			fmt.Fprintf(w, "   Optional: %s\n\n", v.Label)
			if v.Attach != nil {
				printCommands(w, []string{"claude mcp remove bank", playground.ClaudeAddCommand(v.Attach, wardenAddr)})
				// A running agent keeps the old headers until it reconnects, and
				// would go on acting as the previous person.
				printReconnectHint(w)
			}
			if v.Ask != "" {
				fmt.Fprintf(w, "   Ask: %q\n\n", v.Ask)
			}
			for _, line := range v.Shows {
				fmt.Fprintf(w, "   - %s\n", line)
			}
			fmt.Fprintln(w)
		}
	}
}

func printReconnectHint(w io.Writer) {
	fmt.Fprintln(w, "   Then reconnect the server in your agent (/mcp in Claude Code), or restart it.")
	fmt.Fprintln(w)
}

func printCommands(w io.Writer, cmds []string) {
	if len(cmds) == 0 {
		return
	}
	for _, c := range cmds {
		for _, line := range strings.Split(c, "\n") {
			fmt.Fprintf(w, "   %s\n", line)
		}
	}
	fmt.Fprintln(w)
}
