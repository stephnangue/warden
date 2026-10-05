package dev

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/stephnangue/warden/internal/playground"
)

// playgroundDir holds the config files the tour writes, away from any real
// project's own. Every path is absolute, so a scenario printed alone writes
// to the same place from whatever directory it is pasted in.
const playgroundDir = `$HOME/warden-playground`

// client is an agent harness the tour prints its commands for. A client
// attaches servers one of two ways: by commands that add and remove one
// (add, remove), or through a config file the tour rewrites whole each time
// the attached servers change (file).
type client struct {
	name string
	// add and remove print the commands that attach and detach one server.
	add    func(a *playground.Attachment, wardenAddr string) string
	remove func(server string) string
	// file prints the command that writes the whole config, with every
	// attached server in it and the variables exported to the agent so far.
	// Set instead of add and remove.
	file func(attached []*playground.Attachment, exported []string, wardenAddr string) string
	// setup are commands run once, after the identities are minted.
	setup []string
	// launch is printed after the setup: where to start the agent, so it
	// reads what the tour attaches. It always opens with agentTab.
	launch string
	// reconnect tells the reader how the running agent picks up a change.
	reconnect string
	// restart tells the reader how to restart the agent, in its own tab, so
	// it inherits the variables loaded there.
	restart string
	// rawResult, when set, says how to see a tool's raw result.
	rawResult string
	// instructions names the file, in the playground directory, the client
	// reads the agent's instructions from. Empty: the tour writes none.
	instructions string
}

// agentTab opens every launch line. The agent runs in a shell of its own,
// never in the one that ran the setup: that shell holds the root token, and an
// agent that inherited it could rewrite the very policies the tour shows it
// cannot get past.
const agentTab = "Start your agent in a new terminal tab, never in this one: this shell holds the root token, " +
	"and an agent that inherited it could rewrite the policies the tour shows it cannot get past."

// agentEnv is the file, in the playground directory, that hands the agent's
// own tab the variables a scenario exports: the setup's shell, which has
// them, is not the one the agent runs in.
const agentEnv = "agent.env"

// clients are the harnesses the tour knows, by the name -client takes.
var clients = map[string]client{
	"claude": {
		name:   "claude",
		add:    claudeAdd,
		remove: func(server string) string { return "claude mcp remove " + server },
		// claude mcp add attaches a server to the directory it runs in, so the
		// setup and the agent's tab share one.
		setup: []string{"mkdir -p " + playgroundDir + " && cd " + playgroundDir},
		launch: agentTab + " Once scenario 1 has added the bank, run there: cd " + playgroundDir + " && claude. " +
			"Claude Code reads the servers added in that directory.",
		reconnect: "reconnect the server in your agent (/mcp in Claude Code), or restart it",
		restart:   "exit Claude Code, then run claude again",
		rawResult: "In Claude Code, press ctrl+o.",
	},
	"gemini": {
		name:   "gemini",
		add:    geminiAdd,
		remove: func(server string) string { return "gemini mcp remove " + server },
		setup:  []string{"mkdir -p " + playgroundDir + " && cd " + playgroundDir},
		launch: agentTab + " Once scenario 1 has added the bank, run there: cd " + playgroundDir + " && gemini. " +
			"Trust the folder when it asks: it reads the servers from .gemini/settings.json there.",
		// /mcp refresh reconnects the servers Gemini CLI started with; it does
		// not read the settings again.
		reconnect:    "restart Gemini CLI",
		restart:      "exit Gemini CLI, then run gemini again",
		instructions: "GEMINI.md",
	},
	"codex": {
		name: "codex",
		file: codexConfig,
		launch: agentTab + " Once scenario 1 has written the bank, run there: cd " + playgroundDir + " && codex. " +
			"Trust the directory when Codex asks: it reads the servers from .codex/config.toml there.",
		reconnect:    "restart Codex",
		restart:      "exit Codex, then run codex again",
		instructions: "AGENTS.md",
	},
	"cursor": {
		name: "cursor",
		file: cursorConfig,
		launch: agentTab + " Once scenario 1 has written the bank, quit Cursor fully and run there: cursor " + playgroundDir + ". " +
			"An open Cursor never sees that tab's variables, and scenario 8 needs them. Approve the MCP servers when it asks.",
		// Cursor can keep a server's old tools across a reconnect; a restart
		// is the reliable way.
		reconnect:    "quit Cursor fully, then run cursor " + playgroundDir + " again",
		restart:      "quit Cursor fully, then run cursor " + playgroundDir + " again",
		instructions: "AGENTS.md",
	},
	"vscode": {
		name: "vscode",
		file: vscodeConfig,
		launch: agentTab + " Once scenario 1 has written the bank, quit VS Code fully and run there: code " + playgroundDir + ". " +
			"An open VS Code never sees that tab's variables, and scenario 8 needs them. Trust the workspace when it asks.",
		reconnect:    "send your next message: VS Code restarts a server whose config changed. If it does not, MCP: List Servers > Restart",
		restart:      "quit VS Code fully, then run code " + playgroundDir + " again",
		instructions: "AGENTS.md",
	},
	"opencode": {
		name:         "opencode",
		file:         opencodeConfig,
		launch:       agentTab + " Once scenario 1 has written the bank, run there: cd " + playgroundDir + " && opencode. It reads the servers from opencode.json there.",
		reconnect:    "restart opencode",
		restart:      "exit opencode, then run opencode again",
		instructions: "AGENTS.md",
	},
	"generic": {
		name:      "generic",
		add:       genericAdd,
		remove:    func(server string) string { return `# Remove the MCP server "` + server + `" from your client.` },
		launch:    agentTab,
		reconnect: "reconnect the server in your agent, or restart it",
		restart:   "restart your agent",
	},
}

// clientNames lists the names -client takes, sorted.
func clientNames() []string {
	names := make([]string, 0, len(clients))
	for name := range clients {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// claudeAdd renders the claude mcp add line for an attachment.
func claudeAdd(a *playground.Attachment, wardenAddr string) string {
	var b strings.Builder
	b.WriteString("claude mcp add --transport http " + a.Server + ` "` + wardenAddr + a.Path + `"`)
	for _, h := range a.Headers {
		b.WriteString(` \` + "\n  --header \"" + h.Name + ": " + h.Value + `"`)
	}
	return b.String()
}

// geminiAdd renders the gemini mcp add line for an attachment. It writes
// .gemini/settings.json in the directory it runs in.
func geminiAdd(a *playground.Attachment, wardenAddr string) string {
	var b strings.Builder
	b.WriteString("gemini mcp add -t http " + a.Server + ` "` + wardenAddr + a.Path + `"`)
	for _, h := range a.Headers {
		b.WriteString(` \` + "\n  -H \"" + h.Name + ": " + h.Value + `"`)
	}
	return b.String()
}

// genericAdd prints what to enter in a client the tour has no commands for,
// with the shell's values filled in.
func genericAdd(a *playground.Attachment, wardenAddr string) string {
	var b strings.Builder
	b.WriteString("cat <<EOF\n")
	b.WriteString("Add this MCP server to your client (streamable HTTP):\n")
	b.WriteString("  Name:   " + a.Server + "\n")
	b.WriteString("  URL:    " + wardenAddr + a.Path + "\n")
	for _, h := range a.Headers {
		b.WriteString("  Header: " + h.Name + ": " + h.Value + "\n")
	}
	b.WriteString("EOF")
	return b.String()
}

// writeFile renders the command that writes body to path, under the
// playground directory. The heredoc's delimiter is unquoted, so the shell
// fills in the header values ($AGENT, $(warden dev jwt ...)) as it writes:
// the file holds the tokens themselves, and a client never has to inherit the
// shell's environment to read them.
func writeFile(path, body string) string {
	return writeHeredoc(path, body, "EOF")
}

// writeAgentEnv renders the command that writes the variables handed to the
// agent to agentEnv, for its own tab to source. The shell fills in the values
// as it writes, as it does the headers; a token or a URL holds no single
// quote, so each value is quoted with them.
func writeAgentEnv(exported []string) string {
	lines := make([]string, len(exported))
	for i, name := range exported {
		lines[i] = "export " + name + "='$" + name + "'"
	}
	return writeFile(agentEnv, strings.Join(lines, "\n"))
}

// sourceAgentEnv is the command the agent's tab runs to load agentEnv.
const sourceAgentEnv = "source " + playgroundDir + "/" + agentEnv

// writeInstructions renders the command that writes the agent's instructions
// to path, under the playground directory, as they are: the delimiter is
// quoted, so the shell expands nothing in them.
func writeInstructions(path, body string) string {
	return writeHeredoc(path, strings.TrimSuffix(body, "\n"), "'EOF'")
}

func writeHeredoc(path, body, delimiter string) string {
	dir := playgroundDir
	if i := strings.LastIndex(path, "/"); i >= 0 {
		dir += "/" + path[:i]
	}
	return `mkdir -p "` + dir + `" && cat > "` + playgroundDir + "/" + path + `" <<` + delimiter + "\n" + body + "\nEOF"
}

func headerMap(a *playground.Attachment) map[string]string {
	headers := make(map[string]string, len(a.Headers))
	for _, h := range a.Headers {
		headers[h.Name] = h.Value
	}
	return headers
}

// marshalConfig indents v as JSON, leaving &, < and > as they are: the shell
// reads them in the heredoc, not a browser.
func marshalConfig(v any) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
	return strings.TrimSuffix(buf.String(), "\n")
}

func cursorConfig(attached []*playground.Attachment, _ []string, wardenAddr string) string {
	type server struct {
		URL     string            `json:"url"`
		Headers map[string]string `json:"headers"`
	}
	servers := map[string]server{}
	for _, a := range attached {
		servers[a.Server] = server{URL: wardenAddr + a.Path, Headers: headerMap(a)}
	}
	return writeFile(".cursor/mcp.json", marshalConfig(map[string]any{"mcpServers": servers}))
}

func vscodeConfig(attached []*playground.Attachment, _ []string, wardenAddr string) string {
	type server struct {
		Type    string            `json:"type"`
		URL     string            `json:"url"`
		Headers map[string]string `json:"headers"`
	}
	servers := map[string]server{}
	for _, a := range attached {
		servers[a.Server] = server{Type: "http", URL: wardenAddr + a.Path, Headers: headerMap(a)}
	}
	return writeFile(".vscode/mcp.json", marshalConfig(map[string]any{"servers": servers}))
}

func opencodeConfig(attached []*playground.Attachment, _ []string, wardenAddr string) string {
	type server struct {
		Type    string            `json:"type"`
		URL     string            `json:"url"`
		Enabled bool              `json:"enabled"`
		Headers map[string]string `json:"headers"`
	}
	servers := map[string]server{}
	for _, a := range attached {
		servers[a.Server] = server{Type: "remote", URL: wardenAddr + a.Path, Enabled: true, Headers: headerMap(a)}
	}
	return writeFile("opencode.json", marshalConfig(map[string]any{
		"$schema": "https://opencode.ai/config.json",
		"mcp":     servers,
	}))
}

// codexAgentShell hands the exported variables to the commands Codex runs in
// the playground directory, once a scenario hands them to the agent: scenario
// 8, whose agent calls the bank's HTTP API with curl. Until then the agent
// holds no token and calls nothing itself, so neither is set. Codex runs the
// commands with the network off by default; MCP calls are Codex's own, and
// work without it. The values are filled in by the shell as it writes the
// file, as the headers are, so the commands have them however Codex was
// started. sandbox_mode is top-level, so it comes before any table.
func codexAgentShell(exported []string) string {
	pairs := make([]string, len(exported))
	for i, name := range exported {
		pairs[i] = strconv.Quote(name) + " = " + strconv.Quote("$"+name)
	}
	return "sandbox_mode = \"workspace-write\"\n\n" +
		"[sandbox_workspace_write]\nnetwork_access = true\n\n" +
		"[shell_environment_policy]\nset = { " + strings.Join(pairs, ", ") + " }\n"
}

// codexConfig writes Codex's TOML by hand: the shape is two keys a server.
func codexConfig(attached []*playground.Attachment, exported []string, wardenAddr string) string {
	sorted := append([]*playground.Attachment(nil), attached...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Server < sorted[j].Server })
	var sections []string
	if len(exported) > 0 {
		sections = append(sections, codexAgentShell(exported))
	}
	for _, a := range sorted {
		headers := headerMap(a)
		names := make([]string, 0, len(headers))
		for name := range headers {
			names = append(names, name)
		}
		sort.Strings(names)
		pairs := make([]string, len(names))
		for j, name := range names {
			pairs[j] = strconv.Quote(name) + " = " + strconv.Quote(headers[name])
		}
		var b strings.Builder
		fmt.Fprintf(&b, "[mcp_servers.%s]\n", a.Server)
		fmt.Fprintf(&b, "url = %s\n", strconv.Quote(wardenAddr+a.Path))
		fmt.Fprintf(&b, "http_headers = { %s }\n", strings.Join(pairs, ", "))
		sections = append(sections, b.String())
	}
	return writeFile(".codex/config.toml", strings.TrimSuffix(strings.Join(sections, "\n"), "\n"))
}
