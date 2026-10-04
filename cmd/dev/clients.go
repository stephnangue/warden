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
	// attached server in it. Set instead of add and remove.
	file func(attached []*playground.Attachment, wardenAddr string) string
	// setup are commands run once, after the identities are minted.
	setup []string
	// launch is printed after the setup: where to start the agent, so it
	// reads what the tour attaches.
	launch string
	// reconnect tells the reader how the running agent picks up a change.
	reconnect string
	// restart tells the reader how to restart the agent so it inherits the
	// shell's exports.
	restart string
	// rawResult, when set, says how to see a tool's raw result.
	rawResult string
}

// clients are the harnesses the tour knows, by the name -client takes.
var clients = map[string]client{
	"claude": {
		name:      "claude",
		add:       claudeAdd,
		remove:    func(server string) string { return "claude mcp remove " + server },
		reconnect: "reconnect the server in your agent (/mcp in Claude Code), or restart it",
		restart:   "exit Claude Code, then run claude again from this shell",
		rawResult: "In Claude Code, press ctrl+o.",
	},
	"gemini": {
		name:   "gemini",
		add:    geminiAdd,
		remove: func(server string) string { return "gemini mcp remove " + server },
		setup:  []string{"mkdir -p " + playgroundDir + " && cd " + playgroundDir},
		launch: "Once scenario 1 has added the bank, start Gemini CLI from this directory and this shell: gemini. " +
			"Trust the folder when it asks: it reads the servers from .gemini/settings.json here.",
		// /mcp refresh reconnects the servers Gemini CLI started with; it does
		// not read the settings again.
		reconnect: "restart Gemini CLI from this directory",
		restart:   "exit Gemini CLI, then run gemini again from this shell",
	},
	"codex": {
		name: "codex",
		file: codexConfig,
		launch: "Once scenario 1 has written the bank, start Codex from this shell: cd " + playgroundDir + " && codex. " +
			"Trust the directory when Codex asks: it reads the servers from .codex/config.toml there.",
		reconnect: "restart Codex",
		restart:   "exit Codex, then run codex again from this shell",
	},
	"cursor": {
		name: "cursor",
		file: cursorConfig,
		launch: "Once scenario 1 has written the bank, quit Cursor fully and start it from this shell: cursor " + playgroundDir + ". " +
			"An open Cursor never sees this shell's exports, and scenario 8 needs them. Approve the MCP servers when it asks.",
		// Cursor can keep a server's old tools across a reconnect; a restart
		// is the reliable way.
		reconnect: "quit Cursor fully, then run cursor " + playgroundDir + " again",
		restart:   "quit Cursor fully, then run cursor " + playgroundDir + " from this shell",
	},
	"vscode": {
		name: "vscode",
		file: vscodeConfig,
		launch: "Once scenario 1 has written the bank, quit VS Code fully and start it from this shell: code " + playgroundDir + ". " +
			"An open VS Code never sees this shell's exports, and scenario 8 needs them. Trust the workspace when it asks.",
		reconnect: "send your next message: VS Code restarts a server whose config changed. If it does not, MCP: List Servers > Restart",
		restart:   "quit VS Code fully, then run code " + playgroundDir + " from this shell",
	},
	"opencode": {
		name:      "opencode",
		file:      opencodeConfig,
		launch:    "Once scenario 1 has written the bank, start opencode from this shell: cd " + playgroundDir + " && opencode. It reads the servers from opencode.json there.",
		reconnect: "restart opencode",
		restart:   "exit opencode, then run opencode again from this shell",
	},
	"generic": {
		name:      "generic",
		add:       genericAdd,
		remove:    func(server string) string { return `# Remove the MCP server "` + server + `" from your client.` },
		reconnect: "reconnect the server in your agent, or restart it",
		restart:   "restart your agent from this shell",
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
	dir := playgroundDir
	if i := strings.LastIndex(path, "/"); i >= 0 {
		dir += "/" + path[:i]
	}
	return `mkdir -p "` + dir + `" && cat > "` + playgroundDir + "/" + path + `" <<EOF` + "\n" + body + "\nEOF"
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

func cursorConfig(attached []*playground.Attachment, wardenAddr string) string {
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

func vscodeConfig(attached []*playground.Attachment, wardenAddr string) string {
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

func opencodeConfig(attached []*playground.Attachment, wardenAddr string) string {
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

// codexConfig writes Codex's TOML by hand: the shape is two keys a server.
func codexConfig(attached []*playground.Attachment, wardenAddr string) string {
	sorted := append([]*playground.Attachment(nil), attached...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Server < sorted[j].Server })
	var b strings.Builder
	for i, a := range sorted {
		if i > 0 {
			b.WriteString("\n")
		}
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
		fmt.Fprintf(&b, "[mcp_servers.%s]\n", a.Server)
		fmt.Fprintf(&b, "url = %s\n", strconv.Quote(wardenAddr+a.Path))
		fmt.Fprintf(&b, "http_headers = { %s }\n", strings.Join(pairs, ", "))
	}
	return writeFile(".codex/config.toml", strings.TrimSuffix(b.String(), "\n"))
}
