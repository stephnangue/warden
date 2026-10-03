package core

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"time"

	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/internal/playground"
	"github.com/stephnangue/warden/logical"
)

// DevPlayground is what a dev server started with -dev-playground hands the core:
// the fixtures behind the sys/dev paths. Every other server leaves it nil, and
// those paths do not exist.
type DevPlayground interface {
	MintIdentity(playground.Identity) (string, error)
	Scenarios() []playground.Scenario
	AuditPath() string
}

// devAuditTailBytes bounds how much of the playground's audit log one read scans.
const devAuditTailBytes = 8 << 20

// pathDev returns the dev playground's paths, or none outside the playground.
func (b *SystemBackend) pathDev() []*framework.Path {
	if b.core.devPlayground == nil {
		return nil
	}
	return []*framework.Path{
		{
			Pattern: "dev/jwt",
			Fields: map[string]*framework.FieldSchema{
				"kind":    {Type: framework.TypeString, Description: `"agent" or "user".`},
				"sub":     {Type: framework.TypeString, Description: "The identity's subject."},
				"may_act": {Type: framework.TypeString, Description: "For a user: the agent allowed to act for them."},
				"claims":  {Type: framework.TypeMap, Description: "Extra claims, such as a team."},
				"ttl":     {Type: framework.TypeDurationSecond, Description: "Lifetime (default 1h, at most 24h)."},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{Callback: b.handleDevJWT, Summary: "Mint a playground identity"},
				logical.UpdateOperation: &framework.PathOperation{Callback: b.handleDevJWT, Summary: "Mint a playground identity"},
			},
			HelpSynopsis: "Mint an agent or user JWT signed by the playground IdP",
		},
		{
			Pattern: "dev/scenarios",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{Callback: b.handleDevScenarios, Summary: "List the playground scenarios"},
			},
			HelpSynopsis: "The playground's scenarios, with what to do and what to look for",
		},
		{
			Pattern: "dev/audit",
			Fields: map[string]*framework.FieldSchema{
				"n":         {Type: framework.TypeInt, Default: 20, Description: "How many entries, newest first."},
				"principal": {Type: framework.TypeString, Description: "Only entries for this agent principal."},
				"user":      {Type: framework.TypeString, Description: "Only entries acting for this user."},
				"role":      {Type: framework.TypeString, Description: "Only entries under this role."},
				"decision":  {Type: framework.TypeString, Description: `Only "allow" or "deny" entries.`},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{Callback: b.handleDevAudit, Summary: "Read the playground's audit log"},
			},
			HelpSynopsis: "The latest entries of the playground's audit log",
		},
	}
}

func (b *SystemBackend) handleDevJWT(ctx context.Context, _ *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if resp, ok := b.requireRootNamespace(ctx, "the dev playground"); !ok {
		return resp, nil
	}
	id := playground.Identity{
		Kind:    d.Get("kind").(string),
		Subject: d.Get("sub").(string),
		MayAct:  d.Get("may_act").(string),
		TTL:     time.Duration(d.Get("ttl").(int)) * time.Second,
	}
	if claims, ok := d.GetOk("claims"); ok {
		id.Claims, _ = claims.(map[string]any)
	}
	token, err := b.core.devPlayground.MintIdentity(id)
	if err != nil {
		return logical.ErrorResponse(logical.ErrBadRequest(err.Error())), nil
	}
	return b.respondSuccess(map[string]any{"token": token}), nil
}

func (b *SystemBackend) handleDevScenarios(ctx context.Context, _ *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	if resp, ok := b.requireRootNamespace(ctx, "the dev playground"); !ok {
		return resp, nil
	}
	return b.respondSuccess(map[string]any{
		"setup":     playground.SetupCommands,
		"scenarios": b.core.devPlayground.Scenarios(),
	}), nil
}

// devAuditFilter selects playground audit entries.
type devAuditFilter struct {
	principal, user, role, decision string
}

func (b *SystemBackend) handleDevAudit(ctx context.Context, _ *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if resp, ok := b.requireRootNamespace(ctx, "the dev playground"); !ok {
		return resp, nil
	}
	n := d.Get("n").(int)
	if n <= 0 || n > 1000 {
		return logical.ErrorResponse(logical.ErrBadRequest("n must be between 1 and 1000")), nil
	}
	filter := devAuditFilter{
		principal: d.Get("principal").(string),
		user:      d.Get("user").(string),
		role:      d.Get("role").(string),
		decision:  d.Get("decision").(string),
	}
	if filter.decision != "" && filter.decision != "allow" && filter.decision != "deny" {
		return logical.ErrorResponse(logical.ErrBadRequest(`decision must be "allow" or "deny"`)), nil
	}
	entries, err := readDevAudit(b.core.devPlayground.AuditPath(), n, filter)
	if err != nil {
		return logical.ErrorResponse(logical.ErrBadRequest(err.Error())), nil
	}
	return b.respondSuccess(map[string]any{"entries": entries}), nil
}

// readDevAudit returns up to n request entries from the newest end of the
// playground's audit log, each summarised beside the raw entry. It reads through
// its own handle, so it never contends with the audit device writing the file.
func readDevAudit(path string, n int, filter devAuditFilter) ([]map[string]any, error) {
	tail, err := readFileTail(path, devAuditTailBytes)
	if err != nil {
		if os.IsNotExist(err) {
			return []map[string]any{}, nil
		}
		return nil, fmt.Errorf("read the playground audit log: %w", err)
	}

	// The tail is already in memory and outlives the loop, so lines are slices
	// of it rather than copies.
	lines := bytes.Split(tail, []byte{'\n'})

	out := []map[string]any{}
	for i := len(lines) - 1; i >= 0 && len(out) < n; i-- {
		lines[i] = bytes.TrimSpace(lines[i])
		if len(lines[i]) == 0 {
			continue
		}
		var entry map[string]any
		if json.Unmarshal(lines[i], &entry) != nil {
			continue
		}
		if s, _ := entry["type"].(string); s != "request" {
			continue
		}
		// Only calls through Warden to a provider: the scenarios' traffic, not the
		// operator's own sys/ calls, reading this log included.
		if request, _ := entry["request"].(map[string]any); request["mount_class"] != "provider" {
			continue
		}
		summary := summarizeDevAuditEntry(entry)
		if !filter.matches(summary) {
			continue
		}
		summary["entry"] = entry
		out = append(out, summary)
	}
	return out, nil
}

// readFileTail reads at most limit bytes from the end of path, starting on a line
// boundary. The limit holds even while the file grows under the read.
func readFileTail(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	offset := max(info.Size()-limit, 0)
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(f, limit))
	if err != nil {
		return nil, err
	}
	if offset > 0 {
		if i := bytes.IndexByte(data, '\n'); i >= 0 {
			data = data[i+1:]
		}
	}
	return data, nil
}

// summarizeDevAuditEntry pulls out who acted, for whom, under which role, what
// they called and what Warden decided.
func summarizeDevAuditEntry(entry map[string]any) map[string]any {
	obj := func(m map[string]any, k string) map[string]any { v, _ := m[k].(map[string]any); return v }
	str := func(m map[string]any, k string) string { v, _ := m[k].(string); return v }

	request := obj(entry, "request")
	auth := obj(entry, "auth")
	results := obj(auth, "policy_results")
	mcpDecision := obj(results, "mcp_decision")

	decision, reason := "allow", ""
	if allowed, ok := results["allowed"].(bool); ok && !allowed {
		decision = "deny"
		if cond := obj(results, "condition"); cond != nil {
			reason = "condition: " + str(cond, "expression")
		}
	}
	if mcpDecision != nil && str(mcpDecision, "decision") == "deny" {
		decision = "deny"
		reason = "mcp policy: " + str(mcpDecision, "rule_type")
		if cond := obj(mcpDecision, "condition"); cond != nil {
			reason += " (" + str(cond, "expression") + ")"
		}
	}
	if e := str(entry, "error"); e != "" {
		decision = "deny"
		if reason == "" {
			reason = e
		}
	}

	path := str(request, "path")
	if mount := str(request, "mount_point"); mount != "" && !strings.HasPrefix(path, mount) {
		path = mount + path
	}
	return map[string]any{
		"time":     entry["timestamp"],
		"path":     path,
		"agent":    str(auth, "principal_id"),
		"role":     str(auth, "role_name"),
		"user":     str(obj(auth, "user"), "subject"),
		"tool":     str(mcpDecision, "name"),
		"decision": decision,
		"reason":   reason,
	}
}

func (f devAuditFilter) matches(summary map[string]any) bool {
	// Pairs, not a map keyed by the wanted value: two filters asking for the
	// same value would collapse into one, and only one would be checked.
	for _, c := range [...]struct{ key, want string }{
		{"agent", f.principal}, {"user", f.user}, {"role", f.role}, {"decision", f.decision},
	} {
		if c.want != "" && summary[c.key] != c.want {
			return false
		}
	}
	return true
}

// CheckDevPlaygroundDiscovery resolves discovery as a freshly minted playground
// agent would see it, and fails unless every one of wantRoles is listed with a
// provider, a skill and a url, and discovery raised no warning. Run after the
// bootstrap, it turns a misconfigured provider_path or auto_auth_path into a
// startup error instead of a confusing first run.
func (c *Core) CheckDevPlaygroundDiscovery(ctx context.Context, wantRoles []string) error {
	if c.devPlayground == nil {
		return fmt.Errorf("not a dev playground")
	}
	token, err := c.devPlayground.MintIdentity(playground.Identity{Kind: playground.KindAgent, Subject: "playground-self-check", TTL: time.Minute})
	if err != nil {
		return fmt.Errorf("mint a self-check identity: %w", err)
	}
	httpReq := httptest.NewRequest(http.MethodPost, "/v1/sys/mcp", nil).WithContext(ctx)
	httpReq.Header.Set("Authorization", "Bearer "+token)
	ctx, cancel := sysMCPContext(httpReq, namespace.RootNamespace)
	defer cancel()

	roles, warnings, err := c.resolveDiscovery(ctx)
	if err != nil {
		return fmt.Errorf("resolve discovery: %w", err)
	}
	if len(warnings) > 0 {
		return fmt.Errorf("discovery warnings: %s", strings.Join(warnings, "; "))
	}
	byName := make(map[string]mcpRole, len(roles))
	for _, r := range roles {
		byName[r.Name] = r
	}
	for _, name := range wantRoles {
		r, ok := byName[name]
		switch {
		case !ok:
			return fmt.Errorf("role %q is not listed", name)
		case r.Provider == "" || r.Skill == "" || r.URL == "":
			return fmt.Errorf("role %q is listed without its provider, skill or url (got %q, %q, %q)", name, r.Provider, r.Skill, r.URL)
		}
	}
	return nil
}

// RunDevBootstrap makes the dev playground's bootstrap writes, in order, as the
// root token. Each goes through HandleRequest with a JSON body, exactly as the
// same write from the CLI would, so a step that works here works by hand. The
// first failure stops the bootstrap and names the step.
func (c *Core) RunDevBootstrap(ctx context.Context, rootToken string, steps []playground.Step) error {
	for i, step := range steps {
		method := http.MethodPost
		op := logical.CreateOperation
		if step.Operation == "update" {
			method, op = http.MethodPut, logical.UpdateOperation
		}
		body, err := json.Marshal(step.Data)
		if err != nil {
			return fmt.Errorf("playground bootstrap %s: %w", step.Path, err)
		}
		httpReq := httptest.NewRequest(method, "/v1/"+step.Path, bytes.NewReader(body)).WithContext(ctx)
		httpReq.Header.Set("Content-Type", "application/json")
		httpReq.Header.Set("X-Warden-Token", rootToken)
		// The bootstrap runs in-process; the audit names it as such rather than
		// as httptest's placeholder peer.
		httpReq.RemoteAddr = "127.0.0.1:0"

		resp, err := c.HandleRequest(ctx, &logical.Request{
			Path:        step.Path,
			Operation:   op,
			HTTPRequest: httpReq,
			ClientIP:    "127.0.0.1",
			RequestID:   fmt.Sprintf("playground-bootstrap-%02d", i+1),
		})
		if err != nil {
			return fmt.Errorf("playground bootstrap %s: %w", step.Path, err)
		}
		if resp != nil && resp.IsError() {
			return fmt.Errorf("playground bootstrap %s: %s", step.Path, strings.TrimSpace(fmt.Sprint(resp.Error())))
		}
	}
	return nil
}
