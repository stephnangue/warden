package dev

import (
	"fmt"
	"io"
	"strings"

	"github.com/stephnangue/warden/internal/playground"
)

// docsWardenAddr is the address the docs' tour is written for: the shell
// variable, which every command expands, so a reader who moved the port
// changes the one export that sets it.
const docsWardenAddr = "$WARDEN_ADDR"

// docsSetupAddr is the address the docs' setup exports: the dev server's
// default. The root token is not set here: the page sets it before the setup,
// in a way that depends on how the server runs, and never to a value an agent
// could guess.
const docsSetupAddr = "http://127.0.0.1:8400"

// renderTourMarkdown writes the whole tour for c as Markdown, for the getting
// started page: the steps, commands and hints renderTour prints, laid out for
// a reader who never runs warden dev scenarios. Commands come from the same
// stepCommands, so the page and the CLI cannot disagree on one.
//
// The output is a fragment imported into a page, so it holds no headings (the
// page renders one fragment per client, and their ids would collide) and no
// asides (Starlight applies those to its own pages only).
func renderTourMarkdown(w io.Writer, setup []string, scenarios []playground.Scenario, c client) {
	fmt.Fprintln(w, "**Setup, once.** In the Warden tab, where you set the root token above:")
	fmt.Fprintln(w)
	cmds := append([]string{"export WARDEN_ADDR=" + docsSetupAddr}, setup...)
	writeCodeBlock(w, []string{chainCommands(append(cmds, c.setup...))})
	fmt.Fprintln(w, mdText(c.launch))
	fmt.Fprintln(w)

	var current state
	for _, s := range scenarios {
		before := current
		change := step{detach: s.Detach, attach: s.Attach, export: s.Export, commands: s.Commands}
		current = before.after(change)

		fmt.Fprintf(w, "**%d · %s**\n\n", s.Number, mdText(s.Title))
		cmds := stepCommands(c, before, change, docsWardenAddr)
		if s.Instructions != "" && c.instructions != "" {
			cmds = append(cmds, writeInstructions(c.instructions, s.Instructions))
		}
		if len(cmds) > 0 {
			fmt.Fprintln(w, "In the Warden tab:")
			fmt.Fprintln(w)
			writeCodeBlock(w, cmds)
		}
		switch {
		case len(s.Export) > 0:
			fmt.Fprintf(w, "Then, in the agent's tab, load them and restart your agent: `%s`, then %s.\n\n", sourceAgentEnv, mdText(c.restart))
		case s.Attach != nil && len(before.attached) > 0 || len(s.Detach) > 0:
			writeReconnectMarkdown(w, c)
		}
		if len(s.Ask) > 0 {
			fmt.Fprintln(w, "Ask your agent:")
			fmt.Fprintln(w)
			for _, ask := range s.Ask {
				fmt.Fprintf(w, "> %s\n\n", mdText(ask))
			}
		}
		if s.Then != nil {
			fmt.Fprintf(w, "Then: %s.\n\n", mdText(s.Then.Label))
			writeFollowUpMarkdown(w, c, current, *s.Then)
		}
		fmt.Fprintln(w, "What it shows:")
		fmt.Fprintln(w)
		for _, line := range s.Shows {
			if c.rawResult != "" && strings.Contains(line, "raw tool result") {
				line += " " + c.rawResult
			}
			fmt.Fprintf(w, "- %s\n", mdText(line))
		}
		fmt.Fprintln(w)
		for _, v := range s.Variants {
			fmt.Fprintf(w, "Optional: %s.\n\n", mdText(v.Label))
			writeFollowUpMarkdown(w, c, current, v)
			for _, line := range v.Shows {
				fmt.Fprintf(w, "- %s\n", mdText(line))
			}
			if len(v.Shows) > 0 {
				fmt.Fprintln(w)
			}
		}
	}
}

// writeFollowUpMarkdown is printFollowUp's Markdown: swap the bank, run the
// commands, then ask.
func writeFollowUpMarkdown(w io.Writer, c client, current state, v playground.Variant) {
	if cmds := stepCommands(c, current, step{attach: v.Attach, commands: v.Commands}, docsWardenAddr); len(cmds) > 0 {
		writeCodeBlock(w, cmds)
	}
	if v.Attach != nil {
		writeReconnectMarkdown(w, c)
	}
	if v.Ask != "" {
		fmt.Fprintf(w, "> %s\n\n", mdText(v.Ask))
	}
}

func writeReconnectMarkdown(w io.Writer, c client) {
	fmt.Fprintf(w, "Then %s.\n\n", mdText(c.reconnect))
}

// writeCodeBlock writes commands as one shell block, set apart as
// printCommands sets them apart, flush left so a heredoc's EOF ends it.
func writeCodeBlock(w io.Writer, cmds []string) {
	fmt.Fprintln(w, "```bash")
	for i, c := range cmds {
		fmt.Fprintln(w, c)
		if strings.Contains(c, "\n") && i < len(cmds)-1 {
			fmt.Fprintln(w)
		}
	}
	fmt.Fprintln(w, "```")
	fmt.Fprintln(w)
}

// mdText escapes prose for Markdown. Text between backticks is a code span
// and kept as it is; elsewhere <, > and & are escaped, or Markdown would read
// <owner>/<repo> as HTML tags and drop them.
func mdText(s string) string {
	parts := strings.Split(s, "`")
	for i := 0; i < len(parts); i += 2 {
		parts[i] = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(parts[i])
	}
	return strings.Join(parts, "`")
}
