//go:build e2e

// Package helpers provides shared utilities for e2e tests.
package helpers

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Node ports for the 3-node cluster.
var NodePorts = []int{8500, 8510, 8520}

// E2EDir returns the absolute path to the e2e/ directory.
func E2EDir() string {
	// Walk up from the test binary to find the e2e directory.
	// Tests run from their own package dir (e2e/cluster/, e2e/vault/, etc.)
	wd, _ := os.Getwd()
	for d := wd; d != "/"; d = filepath.Dir(d) {
		if _, err := os.Stat(filepath.Join(d, "e2e", ".root_token")); err == nil {
			return filepath.Join(d, "e2e")
		}
		// Also check if we're inside e2e/ already
		if _, err := os.Stat(filepath.Join(d, ".root_token")); err == nil {
			return d
		}
	}
	// Fallback: assume we're in a subdir of e2e/
	return filepath.Join(wd, "..")
}

// RootToken reads the root token from .root_token file.
func RootToken(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(E2EDir(), ".root_token"))
	if err != nil {
		t.Fatalf("failed to read root token: %v", err)
	}
	return strings.TrimSpace(string(data))
}

// NodeURL returns the base URL for a given port.
func NodeURL(port int) string {
	return fmt.Sprintf("http://127.0.0.1:%d", port)
}

// --- HTTP Helpers ---

// DoRequest makes an HTTP request and returns status code and body.
// Fatals on connection errors — use TryRequest when the node may be down.
func DoRequest(t *testing.T, method, rawURL string, headers map[string]string, body string) (int, []byte) {
	t.Helper()
	status, respBody, err := doHTTP(method, rawURL, headers, body)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	return status, respBody
}

// TryRequest makes an HTTP request, returning (0, nil) on connection errors
// instead of fataling. Use this when probing nodes that may be down.
func TryRequest(method, rawURL string, headers map[string]string, body string) (int, []byte) {
	status, respBody, _ := doHTTP(method, rawURL, headers, body)
	return status, respBody
}

func doHTTP(method, rawURL string, headers map[string]string, body string) (int, []byte, error) {
	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}

	req, err := http.NewRequest(method, rawURL, bodyReader)
	if err != nil {
		return 0, nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if body != "" && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, err
	}
	return resp.StatusCode, respBody, nil
}

// APIRequest makes an authenticated API request using root token.
func APIRequest(t *testing.T, method, path string, port int, body string) (int, []byte) {
	t.Helper()
	token := RootToken(t)
	u := fmt.Sprintf("%s/v1/%s", NodeURL(port), path)
	headers := map[string]string{"X-Warden-Token": token}
	return DoRequest(t, method, u, headers, body)
}

// NSAPIRequest makes a namespace-scoped API request.
func NSAPIRequest(t *testing.T, method, path, namespace string, port int, body string) (int, []byte) {
	t.Helper()
	token := RootToken(t)
	u := fmt.Sprintf("%s/v1/%s", NodeURL(port), path)
	headers := map[string]string{
		"X-Warden-Token":     token,
		"X-Warden-Namespace": namespace,
	}
	return DoRequest(t, method, u, headers, body)
}

// --- JSON Helpers ---

// ParseJSON unmarshals JSON body into a map.
func ParseJSON(t *testing.T, body []byte) map[string]interface{} {
	t.Helper()
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("failed to parse JSON: %v\nbody: %s", err, string(body))
	}
	return result
}

// JSONPath extracts a value from nested JSON using dot-separated path.
// Example: JSONPath(data, "data.path") navigates data["data"]["path"].
func JSONPath(data map[string]interface{}, path string) interface{} {
	parts := strings.Split(path, ".")
	var current interface{} = data
	for _, part := range parts {
		m, ok := current.(map[string]interface{})
		if !ok {
			return nil
		}
		current = m[part]
	}
	return current
}

// JSONString extracts a string value from nested JSON.
func JSONString(t *testing.T, body []byte, path string) string {
	t.Helper()
	data := ParseJSON(t, body)
	val := JSONPath(data, path)
	if val == nil {
		t.Fatalf("JSON path %q not found in: %s", path, string(body))
	}
	s, ok := val.(string)
	if !ok {
		t.Fatalf("JSON path %q is not a string: %v", path, val)
	}
	return s
}

// JSONBool extracts a bool value from nested JSON.
func JSONBool(t *testing.T, body []byte, path string) bool {
	t.Helper()
	data := ParseJSON(t, body)
	val := JSONPath(data, path)
	if val == nil {
		t.Fatalf("JSON path %q not found in: %s", path, string(body))
	}
	b, ok := val.(bool)
	if !ok {
		t.Fatalf("JSON path %q is not a bool: %v", path, val)
	}
	return b
}

// --- Cluster Helpers ---

// GetLeaderPort finds the leader node and returns its port.
func GetLeaderPort(t *testing.T) int {
	t.Helper()
	for _, port := range NodePorts {
		status, _ := TryRequest("GET", fmt.Sprintf("%s/v1/sys/health", NodeURL(port)), nil, "")
		if status == 200 {
			return port
		}
	}
	t.Fatal("no leader found")
	return 0
}

// GetStandbyPort finds a standby node and returns its port.
func GetStandbyPort(t *testing.T) int {
	t.Helper()
	for _, port := range NodePorts {
		status, _ := TryRequest("GET", fmt.Sprintf("%s/v1/sys/health", NodeURL(port)), nil, "")
		if status == 429 {
			return port
		}
	}
	t.Fatal("no standby found")
	return 0
}

// NodeNumberForPort maps port to node number (8500→1, 8510→2, 8520→3).
func NodeNumberForPort(port int) int {
	return (port-8500)/10 + 1
}

// WaitForCluster polls until cluster is healthy (1 leader + 2 standbys).
func WaitForCluster(t *testing.T, maxAttempts int, delay time.Duration) {
	t.Helper()
	for i := 0; i < maxAttempts; i++ {
		leaders, standbys := 0, 0
		for _, port := range NodePorts {
			status, _ := TryRequest("GET", fmt.Sprintf("%s/v1/sys/health", NodeURL(port)), nil, "")
			switch status {
			case 200:
				leaders++
			case 429:
				standbys++
			}
		}
		if leaders == 1 && standbys == 2 {
			return
		}
		time.Sleep(delay)
	}
	t.Fatal("cluster did not become healthy in time")
}

// WaitForLeader polls until a leader is found and returns its port.
func WaitForLeader(t *testing.T, maxAttempts int, delay time.Duration) int {
	t.Helper()
	for i := 0; i < maxAttempts; i++ {
		for _, port := range NodePorts {
			status, _ := TryRequest("GET", fmt.Sprintf("%s/v1/sys/health", NodeURL(port)), nil, "")
			if status == 200 {
				return port
			}
		}
		time.Sleep(delay)
	}
	t.Fatal("no leader found in time")
	return 0
}

// WaitForNodeStatus polls a specific node until it reports the expected status.
func WaitForNodeStatus(t *testing.T, port int, expectedStatus int, maxAttempts int, delay time.Duration) {
	t.Helper()
	for i := 0; i < maxAttempts; i++ {
		status, _ := TryRequest("GET", fmt.Sprintf("%s/v1/sys/health", NodeURL(port)), nil, "")
		if status == expectedStatus {
			return
		}
		time.Sleep(delay)
	}
	t.Fatalf("node on port %d did not reach status %d in time", port, expectedStatus)
}

// KillNode sends a signal to a Warden node.
func KillNode(t *testing.T, nodeNum int, signal string) {
	t.Helper()
	script := filepath.Join(E2EDir(), "tools", "kill_node.sh")
	out, err := runScript(script, fmt.Sprintf("%d", nodeNum), signal)
	if err != nil {
		t.Fatalf("kill_node.sh failed: %v\n%s", err, out)
	}
}

// RestartNode restarts a killed Warden node.
func RestartNode(t *testing.T, nodeNum int) {
	t.Helper()
	script := filepath.Join(E2EDir(), "tools", "restart_node.sh")
	out, err := runScript(script, fmt.Sprintf("%d", nodeNum))
	if err != nil {
		t.Fatalf("restart_node.sh failed: %v\n%s", err, out)
	}
}

// StepDown forces the leader on the given port to step down.
func StepDown(t *testing.T, port int) {
	t.Helper()
	script := filepath.Join(E2EDir(), "tools", "step_down.sh")
	out, err := runScript(script, fmt.Sprintf("%d", port))
	if err != nil {
		t.Fatalf("step_down.sh failed: %v\n%s", err, out)
	}
}

// AssertClusterHealthy runs the assert_cluster_healthy.sh script.
func AssertClusterHealthy(t *testing.T) {
	t.Helper()
	script := filepath.Join(E2EDir(), "tools", "assert_cluster_healthy.sh")
	out, err := runScript(script)
	if err != nil {
		t.Fatalf("cluster is not healthy: %v\n%s", err, out)
	}
}

// --- Auth Helpers ---

// GetJWT obtains a JWT from Hydra via client_credentials grant.
func GetJWT(t *testing.T, clientID, clientSecret string) string {
	t.Helper()
	data := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"scope":         {"api:read api:write"},
	}

	resp, err := http.PostForm("http://localhost:4444/oauth2/token", data)
	if err != nil {
		t.Fatalf("failed to get JWT from Hydra: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("failed to parse Hydra response: %v\n%s", err, string(body))
	}

	token, ok := result["access_token"].(string)
	if !ok || token == "" {
		t.Fatalf("no access_token in Hydra response: %s", string(body))
	}
	return token
}

// GetDefaultJWT obtains a JWT using the default e2e-agent client.
func GetDefaultJWT(t *testing.T) string {
	t.Helper()
	return GetJWT(t, "e2e-agent", "agent-secret")
}

// GetNTWardenToken obtains a Warden token for non-transparent gateway access
// by logging in via JWT with the e2e-nt-reader role.
func GetNTWardenToken(t *testing.T, port int) string {
	t.Helper()
	jwt := GetDefaultJWT(t)

	loginBody := fmt.Sprintf(`{"jwt":"%s","role":"e2e-nt-reader"}`, jwt)
	status, body := DoRequest(t, "POST",
		fmt.Sprintf("%s/v1/auth/jwt/login", NodeURL(port)),
		map[string]string{"Content-Type": "application/json"},
		loginBody,
	)
	if status != 200 && status != 201 {
		t.Fatalf("JWT login failed (status %d): %s", status, string(body))
	}

	token := JSONString(t, body, "data.data.token")
	if token == "" {
		t.Fatalf("no token in login response: %s", string(body))
	}
	return token
}

// --- Vault Gateway Helpers ---

// VaultNTRequest makes a non-transparent Vault gateway request.
func VaultNTRequest(t *testing.T, method, vaultPath string, port int, wardenToken string) (int, []byte) {
	t.Helper()
	u := fmt.Sprintf("%s/v1/vault-nt/gateway/v1/%s", NodeURL(port), vaultPath)
	headers := map[string]string{"X-Warden-Token": wardenToken}
	return DoRequest(t, method, u, headers, "")
}

// VaultTransparentRequest makes a transparent Vault gateway request.
func VaultTransparentRequest(t *testing.T, method, vaultPath, role string, port int, jwt string) (int, []byte) {
	t.Helper()
	u := fmt.Sprintf("%s/v1/vault/role/%s/gateway/v1/%s", NodeURL(port), role, vaultPath)
	headers := map[string]string{"Authorization": "Bearer " + jwt}
	return DoRequest(t, method, u, headers, "")
}

// --- Namespace Vault Gateway Helpers ---

// NSVaultNTRequest makes a namespace-scoped non-transparent Vault gateway request.
func NSVaultNTRequest(t *testing.T, method, vaultPath, namespace string, port int, wardenToken string) (int, []byte) {
	t.Helper()
	u := fmt.Sprintf("%s/v1/vault-nt/gateway/v1/%s", NodeURL(port), vaultPath)
	headers := map[string]string{
		"X-Warden-Token":     wardenToken,
		"X-Warden-Namespace": namespace,
	}
	return DoRequest(t, method, u, headers, "")
}

// NSVaultTransparentRequest makes a namespace-scoped transparent Vault gateway request.
func NSVaultTransparentRequest(t *testing.T, method, vaultPath, role, namespace string, port int, jwt string) (int, []byte) {
	t.Helper()
	u := fmt.Sprintf("%s/v1/vault/role/%s/gateway/v1/%s", NodeURL(port), role, vaultPath)
	headers := map[string]string{
		"Authorization":      "Bearer " + jwt,
		"X-Warden-Namespace": namespace,
	}
	return DoRequest(t, method, u, headers, "")
}

// GetNSNTWardenToken obtains a Warden token for non-transparent gateway access
// within a namespace by logging in via JWT with the e2e-nt-reader role.
func GetNSNTWardenToken(t *testing.T, namespace string, port int) string {
	t.Helper()
	jwt := GetDefaultJWT(t)

	loginBody := fmt.Sprintf(`{"jwt":"%s","role":"e2e-nt-reader"}`, jwt)
	status, body := DoRequest(t, "POST",
		fmt.Sprintf("%s/v1/auth/jwt/login", NodeURL(port)),
		map[string]string{
			"Content-Type":       "application/json",
			"X-Warden-Namespace": namespace,
		},
		loginBody,
	)
	if status != 200 && status != 201 {
		t.Fatalf("NS JWT login failed (status %d): %s", status, string(body))
	}

	token := JSONString(t, body, "data.data.token")
	if token == "" {
		t.Fatalf("no token in NS login response: %s", string(body))
	}
	return token
}

// --- Namespace Setup/Teardown ---

const NSVaultNS = "e2e-ci-ns-gw"

// SetupNSVaultEnv creates a full vault provider environment in a namespace.
func SetupNSVaultEnv(t *testing.T, port int) {
	t.Helper()
	ns := NSVaultNS

	// Create namespace
	APIRequest(t, "POST", "sys/namespaces/"+ns, port, "")

	// Non-transparent vault provider
	NSAPIRequest(t, "POST", "sys/providers/vault-nt", ns, port, `{"type":"vault"}`)
	NSAPIRequest(t, "PUT", "vault-nt/config", ns, port,
		`{"vault_address":"http://127.0.0.1:8200","tls_skip_verify":true,"timeout":"30s"}`)

	// Transparent vault provider
	NSAPIRequest(t, "POST", "sys/providers/vault", ns, port, `{"type":"vault"}`)
	NSAPIRequest(t, "PUT", "vault/config", ns, port,
		`{"vault_address":"http://127.0.0.1:8200","tls_skip_verify":true,"timeout":"30s"}`)

	// Credential source
	NSAPIRequest(t, "POST", "sys/cred/sources/vault-e2e", ns, port,
		`{"type":"hvault","rotation_period":300,"config":{"vault_address":"http://127.0.0.1:8200","auth_method":"approle","role_id":"e2e-approle-role-id-1234","secret_id":"e2e-approle-secret-id-5678","approle_mount":"e2e_approle","role_name":"warden-e2e-role"}}`)

	// Credential spec
	NSAPIRequest(t, "POST", "sys/cred/specs/vault-token-reader", ns, port,
		`{"type":"vault_token","source":"vault-e2e","config":{"mint_method":"vault_token","token_role":"e2e-secrets-reader"}}`)

	// Policies
	NSAPIRequest(t, "POST", "sys/policies/cbp/vault-gateway-access", ns, port,
		`{"policy":"path \"vault/gateway*\" {\n  capabilities = [\"read\",\"create\",\"update\",\"delete\",\"list\"]\n}\npath \"vault/role/+/gateway*\" {\n  capabilities = [\"read\",\"create\",\"update\",\"delete\",\"list\"]\n}"}`)
	NSAPIRequest(t, "POST", "sys/policies/cbp/vault-nt-gateway-access", ns, port,
		`{"policy":"path \"vault-nt/gateway*\" {\n  capabilities = [\"read\",\"create\",\"update\",\"delete\",\"list\"]\n}"}`)

	// JWT auth method
	NSAPIRequest(t, "POST", "sys/auth/jwt", ns, port, `{"type":"jwt"}`)
	NSAPIRequest(t, "PUT", "auth/jwt/config", ns, port,
		`{"mode":"oidc","oidc_discovery_url":"http://localhost:4444","bound_issuer":"http://localhost:4444","token_type":"jwt_role"}`)

	// JWT roles
	NSAPIRequest(t, "POST", "auth/jwt/role/e2e-reader", ns, port,
		`{"token_policies":["vault-gateway-access"],"token_type":"jwt_role","cred_spec_name":"vault-token-reader","user_claim":"sub","token_ttl":3600}`)
	NSAPIRequest(t, "POST", "auth/jwt/role/e2e-nt-reader", ns, port,
		`{"token_policies":["vault-nt-gateway-access"],"token_type":"warden_token","cred_spec_name":"vault-token-reader","user_claim":"sub","token_ttl":3600}`)

	// Enable transparent mode
	NSAPIRequest(t, "POST", "vault/config", ns, port,
		`{"transparent_mode":true,"auto_auth_path":"auth/jwt/"}`)
}

// TeardownNSVaultEnv removes all resources created by SetupNSVaultEnv.
func TeardownNSVaultEnv(t *testing.T, port int) {
	t.Helper()
	ns := NSVaultNS

	NSAPIRequest(t, "DELETE", "sys/providers/vault-nt", ns, port, "")
	NSAPIRequest(t, "DELETE", "sys/providers/vault", ns, port, "")
	NSAPIRequest(t, "DELETE", "sys/cred/specs/vault-token-reader", ns, port, "")
	NSAPIRequest(t, "DELETE", "sys/cred/sources/vault-e2e", ns, port, "")
	NSAPIRequest(t, "DELETE", "sys/auth/jwt", ns, port, "")
	NSAPIRequest(t, "DELETE", "sys/policies/cbp/vault-gateway-access", ns, port, "")
	NSAPIRequest(t, "DELETE", "sys/policies/cbp/vault-nt-gateway-access", ns, port, "")
	time.Sleep(1 * time.Second)

	CleanupNamespaces(t, port, ns)
}

// CleanupNamespaces deletes namespaces in order (deepest first).
func CleanupNamespaces(t *testing.T, port int, paths ...string) {
	t.Helper()
	for _, p := range paths {
		APIRequest(t, "DELETE", "sys/namespaces/"+p, port, "")
		time.Sleep(1 * time.Second)
	}
}

// --- Extended Helpers ---

// GetBothStandbyPorts returns both standby ports.
func GetBothStandbyPorts(t *testing.T) (int, int) {
	t.Helper()
	var ports []int
	for _, port := range NodePorts {
		status, _ := TryRequest("GET", fmt.Sprintf("%s/v1/sys/health", NodeURL(port)), nil, "")
		if status == 429 {
			ports = append(ports, port)
		}
	}
	if len(ports) < 2 {
		t.Fatalf("expected 2 standbys, found %d", len(ports))
	}
	return ports[0], ports[1]
}

// PortForNode maps node number to port (1→8500, 2→8510, 3→8520).
func PortForNode(nodeNum int) int {
	return 8500 + (nodeNum-1)*10
}

// GetNodePID reads the PID file for a node.
func GetNodePID(t *testing.T, nodeNum int) int {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(E2EDir(), ".pids", fmt.Sprintf("node%d.pid", nodeNum)))
	if err != nil {
		t.Fatalf("failed to read PID for node %d: %v", nodeNum, err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		t.Fatalf("invalid PID for node %d: %v", nodeNum, err)
	}
	return pid
}

// SignalNode sends a Unix signal to a node process by PID.
func SignalNode(t *testing.T, nodeNum int, sig syscall.Signal) {
	t.Helper()
	pid := GetNodePID(t, nodeNum)
	if err := syscall.Kill(pid, sig); err != nil {
		t.Fatalf("failed to send signal %v to node %d (pid %d): %v", sig, nodeNum, pid, err)
	}
}

// ReadNodeLog reads the full log file for a node.
func ReadNodeLog(t *testing.T, nodeNum int) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(E2EDir(), ".logs", fmt.Sprintf("node%d.log", nodeNum)))
	if err != nil {
		t.Fatalf("failed to read log for node %d: %v", nodeNum, err)
	}
	return string(data)
}

// GrepNodeLog checks if pattern appears in a node's log file.
func GrepNodeLog(t *testing.T, nodeNum int, pattern string) bool {
	t.Helper()
	log := ReadNodeLog(t, nodeNum)
	return strings.Contains(log, pattern)
}

// LoginJWT logs in with a JWT and role, returns (statusCode, wardenToken).
func LoginJWT(t *testing.T, jwt, role string, port int) (int, string) {
	t.Helper()
	loginBody := fmt.Sprintf(`{"jwt":"%s","role":"%s"}`, jwt, role)
	status, body := DoRequest(t, "POST",
		fmt.Sprintf("%s/v1/auth/jwt/login", NodeURL(port)),
		map[string]string{"Content-Type": "application/json"},
		loginBody,
	)
	if status != 200 && status != 201 {
		return status, ""
	}
	data := ParseJSON(t, body)
	token, _ := JSONPath(data, "data.data.token").(string)
	if token == "" {
		token, _ = JSONPath(data, "data.token_id").(string)
	}
	return status, token
}

// LoginJWTInNS logs in with a JWT and role in a namespace.
func LoginJWTInNS(t *testing.T, jwt, role, namespace string, port int) (int, string) {
	t.Helper()
	loginBody := fmt.Sprintf(`{"jwt":"%s","role":"%s"}`, jwt, role)
	status, body := DoRequest(t, "POST",
		fmt.Sprintf("%s/v1/auth/jwt/login", NodeURL(port)),
		map[string]string{
			"Content-Type":       "application/json",
			"X-Warden-Namespace": namespace,
		},
		loginBody,
	)
	if status != 200 && status != 201 {
		return status, ""
	}
	data := ParseJSON(t, body)
	token, _ := JSONPath(data, "data.data.token").(string)
	if token == "" {
		token, _ = JSONPath(data, "data.token_id").(string)
	}
	return status, token
}

// VaultDirectRequest makes a request directly to Vault (port 8200).
func VaultDirectRequest(t *testing.T, method, vaultPath, body string) (int, []byte) {
	t.Helper()
	u := fmt.Sprintf("http://127.0.0.1:8200/v1/%s", vaultPath)
	headers := map[string]string{"X-Vault-Token": "e2e-vault-root-token"}
	return DoRequest(t, method, u, headers, body)
}

// JSONFloat extracts a float64 from nested JSON.
func JSONFloat(t *testing.T, body []byte, path string) float64 {
	t.Helper()
	data := ParseJSON(t, body)
	val := JSONPath(data, path)
	if val == nil {
		t.Fatalf("JSON path %q not found in: %s", path, string(body))
	}
	f, ok := val.(float64)
	if !ok {
		t.Fatalf("JSON path %q is not a number: %v", path, val)
	}
	return f
}

// --- Load Balancer Helpers ---

// LBPort is the nginx load balancer port (HTTPS).
const LBPort = 8000

// LBNodeURL returns the base URL for the nginx load balancer.
func LBNodeURL() string {
	return fmt.Sprintf("https://127.0.0.1:%d", LBPort)
}

// LBAvailable checks if the nginx load balancer can actually proxy to the
// Warden cluster. We probe /v1/sys/health through the LB rather than the
// nginx-only /nginx-health endpoint, because nginx may be healthy while
// unable to reach the backend nodes (e.g., on Linux CI where nodes bind
// to 127.0.0.1 and host.docker.internal maps to the Docker bridge gateway).
func LBAvailable() bool {
	status, _, _ := doLBHTTP("GET", LBNodeURL()+"/v1/sys/health", nil, "", nil)
	// 200 = active leader, 429 = standby — both mean proxying works
	return status == 200 || status == 429
}

// SkipWithoutLB skips the test if the load balancer is not available.
func SkipWithoutLB(t *testing.T) {
	t.Helper()
	if !LBAvailable() {
		t.Skip("nginx load balancer not available (skipping LB test)")
	}
}

// doLBHTTP makes an HTTPS request through the LB with optional TLS client cert.
func doLBHTTP(method, rawURL string, headers map[string]string, body string, clientCert *tls.Certificate) (int, []byte, error) {
	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}

	req, err := http.NewRequest(method, rawURL, bodyReader)
	if err != nil {
		return 0, nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if body != "" && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}

	tlsConfig := &tls.Config{InsecureSkipVerify: true} //nolint:gosec // self-signed e2e cert
	if clientCert != nil {
		tlsConfig.Certificates = []tls.Certificate{*clientCert}
	}

	client := &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsConfig},
	}

	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, err
	}
	return resp.StatusCode, respBody, nil
}

// DoLBRequest makes an HTTPS request through the LB. Fatals on connection errors.
func DoLBRequest(t *testing.T, method, rawURL string, headers map[string]string, body string, clientCert *tls.Certificate) (int, []byte) {
	t.Helper()
	status, respBody, err := doLBHTTP(method, rawURL, headers, body, clientCert)
	if err != nil {
		t.Fatalf("LB request failed: %v", err)
	}
	return status, respBody
}

// parseTLSCert parses PEM-encoded cert+key into a tls.Certificate.
func parseTLSCert(t *testing.T, certPEM, keyPEM string) tls.Certificate {
	t.Helper()
	cert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		t.Fatalf("failed to parse TLS client cert: %v", err)
	}
	return cert
}

// VaultTransparentRequestViaLB makes a JWT transparent vault gateway request through the LB.
func VaultTransparentRequestViaLB(t *testing.T, method, vaultPath, role, jwt string) (int, []byte) {
	t.Helper()
	u := fmt.Sprintf("%s/v1/vault/role/%s/gateway/v1/%s", LBNodeURL(), role, vaultPath)
	headers := map[string]string{"Authorization": "Bearer " + jwt}
	return DoLBRequest(t, method, u, headers, "", nil)
}

// VaultCertTransparentRequestViaLB makes a cert transparent vault gateway request
// through the LB. The client presents its TLS certificate to nginx, which
// validates it against the LB CA and forwards it via X-SSL-Client-Cert.
func VaultCertTransparentRequestViaLB(t *testing.T, method, vaultPath, role, clientCertPEM, clientKeyPEM string) (int, []byte) {
	t.Helper()
	cert := parseTLSCert(t, clientCertPEM, clientKeyPEM)
	u := fmt.Sprintf("%s/v1/vault-cert/role/%s/gateway/v1/%s", LBNodeURL(), role, vaultPath)
	return DoLBRequest(t, method, u, nil, "", &cert)
}

// VaultNTRequestViaLB makes a non-transparent vault gateway request through the LB.
func VaultNTRequestViaLB(t *testing.T, method, vaultPath, wardenToken string) (int, []byte) {
	t.Helper()
	u := fmt.Sprintf("%s/v1/vault-nt/gateway/v1/%s", LBNodeURL(), vaultPath)
	headers := map[string]string{"X-Warden-Token": wardenToken}
	return DoLBRequest(t, method, u, headers, "", nil)
}

// LoginJWTViaLB logs in with a JWT and role through the load balancer.
func LoginJWTViaLB(t *testing.T, jwt, role string) (int, string) {
	t.Helper()
	loginBody := fmt.Sprintf(`{"jwt":"%s","role":"%s"}`, jwt, role)
	status, body := DoLBRequest(t, "POST",
		fmt.Sprintf("%s/v1/auth/jwt/login", LBNodeURL()),
		map[string]string{"Content-Type": "application/json"},
		loginBody, nil,
	)
	if status != 200 && status != 201 {
		return status, ""
	}
	data := ParseJSON(t, body)
	token, _ := JSONPath(data, "data.data.token").(string)
	if token == "" {
		token, _ = JSONPath(data, "data.token_id").(string)
	}
	return status, token
}

// CertLoginRequestViaLB performs a cert auth login through the load balancer.
// The client presents its TLS certificate to nginx for forwarding.
func CertLoginRequestViaLB(t *testing.T, role, clientCertPEM, clientKeyPEM string) (int, []byte) {
	t.Helper()
	cert := parseTLSCert(t, clientCertPEM, clientKeyPEM)
	u := fmt.Sprintf("%s/v1/auth/cert/login", LBNodeURL())
	headers := map[string]string{"Content-Type": "application/json"}
	body := fmt.Sprintf(`{"role":"%s"}`, role)
	return DoLBRequest(t, "POST", u, headers, body, &cert)
}
