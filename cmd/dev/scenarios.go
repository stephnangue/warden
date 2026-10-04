package dev

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"slices"
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

  The commands attach the servers in Claude Code. -client prints them for
  another agent: codex, cursor, gemini, opencode or vscode, or generic for
  the URL and headers to enter in any other. WARDEN_DEV_CLIENT sets it once.

      $ warden dev scenarios -client cursor
`,
	Args: cobra.MaximumNArgs(1),
	RunE: runScenarios,
}

var scenariosClient string

func init() {
	ScenariosCmd.Flags().StringVar(&scenariosClient, "client", "",
		"The agent to print commands for: "+strings.Join(clientNames(), ", ")+" (default claude, or WARDEN_DEV_CLIENT)")
}

type scenariosResponse struct {
	Setup     []string              `json:"setup"`
	Scenarios []playground.Scenario `json:"scenarios"`
}

// resolveClient picks the client from -client, then WARDEN_DEV_CLIENT, then
// claude.
func resolveClient() (client, error) {
	name := scenariosClient
	if name == "" {
		name = os.Getenv("WARDEN_DEV_CLIENT")
	}
	if name == "" {
		name = "claude"
	}
	c, ok := clients[strings.ToLower(strings.TrimSpace(name))]
	if !ok {
		return client{}, fmt.Errorf("unknown client %q, expected one of %s: %w", name, strings.Join(clientNames(), ", "), helpers.ErrUsage)
	}
	return c, nil
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
	agent, err := resolveClient()
	if err != nil {
		return err
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
	renderTour(cmd.OutOrStdout(), resp, only, c.Address(), agent)
	return nil
}

// attachments are the servers attached to the agent's client.
type attachments []*playground.Attachment

// with returns the attachments once detach are removed and a is attached, in
// place of the server of its name.
func (as attachments) with(detach []string, a *playground.Attachment) attachments {
	out := make(attachments, 0, len(as)+1)
	for _, cur := range as {
		if slices.Contains(detach, cur.Server) || a != nil && cur.Server == a.Server {
			continue
		}
		out = append(out, cur)
	}
	if a != nil {
		out = append(out, a)
	}
	return out
}

func (as attachments) has(server string) bool {
	return slices.ContainsFunc(as, func(a *playground.Attachment) bool { return a.Server == server })
}

// stepCommands are the commands of one step of the tour: detach, configure,
// then attach. A client with a config file gets the whole file, rewritten
// with what is attached after the step.
func stepCommands(c client, before attachments, detach []string, a *playground.Attachment, commands []string, wardenAddr string) []string {
	if c.file != nil {
		cmds := append([]string(nil), commands...)
		if len(detach) > 0 || a != nil {
			cmds = append(cmds, c.file(before.with(detach, a), wardenAddr))
		}
		return cmds
	}
	var cmds []string
	for _, server := range detach {
		cmds = append(cmds, c.remove(server))
	}
	// A server is replaced, never added beside another of its name.
	if a != nil && before.has(a.Server) {
		cmds = append(cmds, c.remove(a.Server))
	}
	// Configure first, then connect.
	cmds = append(cmds, commands...)
	if a != nil {
		cmds = append(cmds, c.add(a, wardenAddr))
	}
	return cmds
}

// renderTour prints the scenarios as a walkthrough. only selects one scenario;
// 0 prints them all, with the setup first.
func renderTour(w io.Writer, resp scenariosResponse, only int, wardenAddr string, c client) {
	if only == 0 {
		fmt.Fprintln(w, "Setup, once:")
		fmt.Fprintln(w)
		setup := append([]string{"export WARDEN_ADDR=" + wardenAddr}, resp.Setup...)
		printCommands(w, append(setup, c.setup...))
		if c.launch != "" {
			fmt.Fprintf(w, "   %s\n\n", c.launch)
		}
	}
	// Scenarios run in order, each keeping what the last one attached: one
	// printed alone still knows what is attached when it starts.
	var attached attachments
	for _, s := range resp.Scenarios {
		before := attached
		attached = before.with(s.Detach, s.Attach)
		if only != 0 && s.Number != only {
			continue
		}
		fmt.Fprintf(w, "%d. %s\n\n", s.Number, s.Title)
		printCommands(w, stepCommands(c, before, s.Detach, s.Attach, s.Commands, wardenAddr))
		switch {
		case s.Restart:
			fmt.Fprintf(w, "   Then restart your agent, so it inherits the exports: %s.\n\n", c.restart)
		case s.Attach != nil && len(before) > 0 || len(s.Detach) > 0:
			printReconnectHint(w, c)
		}
		for _, ask := range s.Ask {
			fmt.Fprintf(w, "   Ask: %q\n", ask)
		}
		if len(s.Ask) > 0 {
			fmt.Fprintln(w)
		}
		// The next step comes after the questions: run before them, it would
		// change what they show.
		if s.Then != nil {
			fmt.Fprintf(w, "   Then: %s\n\n", s.Then.Label)
			printFollowUp(w, c, attached, *s.Then, wardenAddr)
		}
		fmt.Fprintln(w, "   What it shows:")
		for _, line := range s.Shows {
			// The client's own way to the raw result follows the line that
			// asks for it.
			if c.rawResult != "" && strings.Contains(line, "raw tool result") {
				line += " " + c.rawResult
			}
			fmt.Fprintf(w, "   - %s\n", line)
		}
		fmt.Fprintln(w)
		// A variant starts from what the scenario attached; the next scenario
		// attaches its own bank again.
		for _, v := range s.Variants {
			fmt.Fprintf(w, "   Optional: %s\n\n", v.Label)
			printFollowUp(w, c, attached, v, wardenAddr)
			for _, line := range v.Shows {
				fmt.Fprintf(w, "   - %s\n", line)
			}
			fmt.Fprintln(w)
		}
	}
}

// printFollowUp prints what a follow-up asks the reader to do: swap the bank,
// run its commands, then ask its question.
func printFollowUp(w io.Writer, c client, attached attachments, v playground.Variant, wardenAddr string) {
	printCommands(w, stepCommands(c, attached, nil, v.Attach, v.Commands, wardenAddr))
	if v.Attach != nil {
		// A running agent keeps the old headers until it reconnects, and
		// would go on acting as the previous person.
		printReconnectHint(w, c)
	}
	if v.Ask != "" {
		fmt.Fprintf(w, "   Ask: %q\n\n", v.Ask)
	}
}

func printReconnectHint(w io.Writer, c client) {
	fmt.Fprintf(w, "   Then %s.\n\n", c.reconnect)
}

// printCommands prints commands flush left, unlike the prose around them, so
// they paste as they are: a shell ends a heredoc only on a line that is its
// delimiter alone, and an indented EOF would leave it waiting for more.
func printCommands(w io.Writer, cmds []string) {
	if len(cmds) == 0 {
		return
	}
	for i, c := range cmds {
		lines := strings.Split(c, "\n")
		for _, line := range lines {
			fmt.Fprintln(w, line)
		}
		// A command that spans lines is set apart from the next one.
		if len(lines) > 1 && i < len(cmds)-1 {
			fmt.Fprintln(w)
		}
	}
	fmt.Fprintln(w)
}
