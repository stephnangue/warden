//go:build e2e

package helpers

import (
	"crypto/ecdsa"
	"fmt"
	"net/http"
	"net/http/cgi"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// --- Git smart-HTTP test environment ---
//
// Git is the one transport where both principals ride in a single header: the
// agent's role in the Basic username, the user credential in the Basic
// password. It is also the only one whose client refuses to send either until
// challenged, so the negotiation itself is part of what has to be tested — and
// none of it is reachable without a git upstream to negotiate with.
//
// Two upstreams are provided. The recording one proves what Warden did with a
// request and, more importantly, what it forwarded: that the user's credential
// never proxies onward and what arrives is the minted one. The real one proves
// that git itself accepts the exchange, which no amount of hand-shaped HTTP can
// establish.

const (
	// GitMount is the provider mount under test, opted into the user leg.
	GitMount = "github-git"

	// GitMountDescription is what protected resource metadata reports as
	// resource_name.
	GitMountDescription = "GitHub git for the e2e platform team"

	// GitUserAuthMount authenticates USER credentials for the git mount. Held
	// apart from the userleg package's mount so the two suites cannot leave
	// state for each other.
	GitUserAuthMount = "auth/git-user-jwt/"

	// GitAgentCertRole is the role certificate agents are granted. Its name is
	// also what a client sends as the Basic username.
	GitAgentCertRole = "e2e-git-agent"

	// GitAgentJWTRole is the equivalent for tests that swap the certificate
	// agent for one on X-Warden-Agent-Token. The stock e2e roles grant
	// vault/gateway*, so reusing one would fail authorization rather than
	// exercise the agent channel under test.
	GitAgentJWTRole = "e2e-git-jwt-agent"

	// GitPAT is the token the credential spec mints. Static by design: PAT mode
	// mints without calling GitHub, so the upstream can be a local server.
	GitPAT = "ghp_e2e_git_smart_http_pat"

	// GitRepo is the repository path served by both upstreams.
	GitRepo = "acme/widgets"
)

// GitUpstreamRequest is one request the recording upstream received.
type GitUpstreamRequest struct {
	Method        string
	Path          string
	RawQuery      string
	Authorization string
	Header        http.Header
}

// GitUpstream is a recording stand-in for GitHub's git smart-HTTP endpoint.
//
// It reproduces the one behaviour the negotiation depends on: an unauthenticated
// request is answered with a Basic challenge rather than served, which is how
// git learns to retry with credentials at all.
type GitUpstream struct {
	URL string

	server *httptest.Server
	mu     sync.Mutex
	reqs   []GitUpstreamRequest
}

// StartGitUpstream starts the recording upstream. The caller owns its lifetime
// via Close: the mount is configured with its URL once for the whole package, so
// binding it to the first test's cleanup would leave every later test pointed at
// a closed listener.
func StartGitUpstream(t *testing.T) *GitUpstream {
	t.Helper()
	u := &GitUpstream{}
	u.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.mu.Lock()
		u.reqs = append(u.reqs, GitUpstreamRequest{
			Method:        r.Method,
			Path:          r.URL.Path,
			RawQuery:      r.URL.RawQuery,
			Authorization: r.Header.Get("Authorization"),
			Header:        r.Header.Clone(),
		})
		u.mu.Unlock()

		if r.Header.Get("Authorization") == "" {
			w.Header().Set("WWW-Authenticate", `Basic realm="github"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/x-git-upload-pack-advertisement")
		w.WriteHeader(http.StatusOK)
		// Enough of a packet stream that a client can tell it was served rather
		// than refused; the tests assert on status and recorded headers, not on
		// git wire semantics.
		_, _ = w.Write([]byte("001e# service=git-upload-pack\n0000"))
	}))
	u.URL = u.server.URL
	return u
}

// Close stops the recording upstream.
func (u *GitUpstream) Close() {
	if u.server != nil {
		u.server.Close()
	}
}

// Requests returns every request received so far.
func (u *GitUpstream) Requests() []GitUpstreamRequest {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]GitUpstreamRequest(nil), u.reqs...)
}

// Last returns the most recent request. Fails the test if there was none.
func (u *GitUpstream) Last(t *testing.T) GitUpstreamRequest {
	t.Helper()
	reqs := u.Requests()
	if len(reqs) == 0 {
		t.Fatal("upstream received no requests")
	}
	return reqs[len(reqs)-1]
}

// Reset clears the recorded requests so one test's traffic cannot be read as
// another's.
func (u *GitUpstream) Reset() {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.reqs = nil
}

// GitExecPath returns git's helper directory, or "" when git is unavailable.
func GitExecPath() string {
	out, err := exec.Command("git", "--exec-path").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// StartRealGitUpstream serves a genuine bare repository over smart-HTTP via
// git-http-backend, so a real `git clone` can be driven end to end. Returns the
// upstream URL, or "" when git-http-backend is unavailable.
//
// Requests without Authorization are refused with a Basic challenge, matching
// the recording upstream and every real host: without it git would clone on the
// first request and the credential slots would never be exercised.
func StartRealGitUpstream(t *testing.T) string {
	t.Helper()

	execPath := GitExecPath()
	if execPath == "" {
		return ""
	}
	backend := filepath.Join(execPath, "git-http-backend")
	if _, err := exec.LookPath(backend); err != nil {
		return ""
	}

	root := t.TempDir()
	repoDir := filepath.Join(root, GitRepo+".git")
	seedBareRepo(t, repoDir)

	handler := &cgi.Handler{
		Path: backend,
		Env: []string{
			"GIT_PROJECT_ROOT=" + root,
			"GIT_HTTP_EXPORT_ALL=1",
		},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.Header().Set("WWW-Authenticate", `Basic realm="github"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// seedBareRepo creates a bare repository with one commit, so a clone produces a
// working tree rather than an empty directory that would pass vacuously.
func seedBareRepo(t *testing.T, bareDir string) {
	t.Helper()

	work := t.TempDir()
	run := func(dir string, args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(cmd.Environ(),
			"GIT_AUTHOR_NAME=e2e", "GIT_AUTHOR_EMAIL=e2e@example.com",
			"GIT_COMMITTER_NAME=e2e", "GIT_COMMITTER_EMAIL=e2e@example.com",
		)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
		}
	}

	write := func(path, content string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}

	run(work, "init", "-q", "-b", "main", work)
	write(filepath.Join(work, "README.md"), "warden e2e fixture\n")
	run(work, "add", "README.md")
	run(work, "commit", "-q", "-m", "seed")
	run(work, "clone", "-q", "--bare", work, bareDir)
	// Without this git-http-backend refuses the fetch as a non-exported repo on
	// hosts where GIT_HTTP_EXPORT_ALL is not honoured.
	write(filepath.Join(bareDir, "git-daemon-export-ok"), "")
}

// SetupGitEnv builds a github mount pointed at upstreamURL whose agent is a
// client certificate and whose user rides the Basic password slot. Returns the
// CA for minting agent certificates.
func SetupGitEnv(t *testing.T, port int, upstreamURL string) (caCertPEM string, caKey *ecdsa.PrivateKey) {
	t.Helper()

	// A previous run that failed mid-setup leaves mounts behind, and every
	// later attempt would then fail with 409 — turning one real failure into a
	// cascade that hides it.
	TeardownGitEnvBestEffort(port)

	caCertPEM, caKey = SetupCertAuth(t, port)

	mustAPI(t, port, "POST", "sys/auth/git-user-jwt", `{"type":"jwt"}`, "mount git-user-jwt auth")
	time.Sleep(time.Second)

	mustAPI(t, port, "PUT", "auth/git-user-jwt/config",
		fmt.Sprintf(`{"mode":"oidc","oidc_discovery_url":"%s","bound_issuer":"%s","bound_audiences":[%q],"user_claim":"sub","entity_kind":"human"}`,
			HydraIssuer, HydraIssuer, HydraAudience),
		"configure git-user-jwt auth")

	mustAPI(t, port, "POST", "sys/providers/"+GitMount,
		fmt.Sprintf(`{"type":"github","description":%q}`, GitMountDescription),
		"mount github provider")
	time.Sleep(time.Second)

	// github_url is used verbatim as the git host for anything that is not
	// api.github.com or a /api/v3 endpoint, which is what lets a local server
	// stand in for GitHub. tls_skip_verify is what permits the http:// scheme;
	// both the provider and the credential source reject plain http without it.
	mustAPI(t, port, "PUT", GitMount+"/config",
		fmt.Sprintf(`{"github_url":%q,"tls_skip_verify":true,"auto_auth_path":"auth/cert/","user_auth_path":%q}`,
			upstreamURL, GitUserAuthMount),
		"configure github provider")

	// PAT mode mints without calling GitHub, so no real credentials are needed
	// and the upstream can be a local server. Source config is string-valued,
	// hence the quoted boolean.
	mustAPI(t, port, "POST", "sys/cred/sources/git-e2e",
		fmt.Sprintf(`{"type":"github","config":{"github_url":%q,"tls_skip_verify":"true"}}`, upstreamURL),
		"create git credential source")

	mustAPI(t, port, "POST", "sys/cred/specs/git-e2e-pat",
		fmt.Sprintf(`{"type":"github_token","source":"git-e2e","config":{"mint_method":"pat","token":%q}}`, GitPAT),
		"create git credential spec")

	mustAPI(t, port, "POST", "sys/policies/cbp/"+GitMount+"-access",
		fmt.Sprintf(`{"policy":"path \"%s/gateway*\" {\n  capabilities = [\"read\",\"create\",\"update\",\"delete\",\"list\"]\n}\npath \"%s/role/+/gateway*\" {\n  capabilities = [\"read\",\"create\",\"update\",\"delete\",\"list\"]\n}"}`,
			GitMount, GitMount),
		"create git policy")

	gitRole := Role{Policies: []string{GitMount + "-access"}, CredSpec: "git-e2e-pat"}
	GrantRole(t, port, "auth/cert/", GitAgentCertRole, gitRole, Rule{"cn": {"agent-*"}})

	// The JWT counterpart, for the header-agent shapes: every agent auth/jwt/
	// admits.
	GrantRole(t, port, "auth/jwt/", GitAgentJWTRole, gitRole, nil)

	return caCertPEM, caKey
}

// SetGitAgentPath repoints the mount's AGENT leg while leaving the user leg
// intact, so a test can swap a certificate agent for a JWT one without
// rebuilding the environment. An empty userAuthPath opts the mount out of the
// user leg entirely, which is how the compatibility cases are exercised.
func SetGitAgentPath(t *testing.T, port int, upstreamURL, autoAuthPath, userAuthPath, defaultRole string) {
	t.Helper()
	body := fmt.Sprintf(`{"github_url":%q,"tls_skip_verify":true,"auto_auth_path":%q,"user_auth_path":%q`,
		upstreamURL, autoAuthPath, userAuthPath)
	if defaultRole != "" {
		body += fmt.Sprintf(`,"default_role":%q`, defaultRole)
	}
	body += "}"
	mustAPI(t, port, "POST", GitMount+"/config", body, "configure git mount")
}

// GitSmartHTTPPath is the info/refs probe path for the fixture repository,
// relative to the mount.
func GitSmartHTTPPath() string {
	return fmt.Sprintf("%s/gateway/%s.git/info/refs?service=git-upload-pack", GitMount, GitRepo)
}

// TeardownGitEnvBestEffort removes everything SetupGitEnv created. Best-effort
// throughout: cleanup must not fail a run that already passed.
func TeardownGitEnvBestEffort(port int) {
	token := rootTokenBestEffort()
	del := func(path string) {
		TryRequest("DELETE", fmt.Sprintf("%s/v1/%s", NodeURL(port), path),
			map[string]string{"X-Warden-Token": token}, "")
	}
	RevokeRoleBestEffort(port, "auth/cert/", GitAgentCertRole)
	RevokeRoleBestEffort(port, "auth/jwt/", GitAgentJWTRole)
	del("sys/policies/cbp/" + GitMount + "-access")
	del("sys/cred/specs/git-e2e-pat")
	del("sys/cred/sources/git-e2e")
	del("sys/providers/" + GitMount)
	del("sys/auth/git-user-jwt")
	del("sys/auth/cert")
	time.Sleep(time.Second)
}
