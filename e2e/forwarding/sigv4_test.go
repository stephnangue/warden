//go:build e2e

package forwarding

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	h "github.com/stephnangue/warden/e2e/helpers"
	"github.com/stephnangue/warden/helper"
)

// setupAWSProvider provisions an AWS provider with local credentials, a
// credential spec, policy, and JWT role so that a client can authenticate
// and receive Warden-issued AWS access keys. Registers cleanup via t.Cleanup.
//
// Cleanup is registered eagerly (before creating resources) so that partial
// failures don't leave orphaned resources. All creates accept 409 (already
// exists) to be idempotent across test runs.
func setupAWSProvider(t *testing.T, port int) {
	t.Helper()

	// Register cleanup first so it always runs, even if creation fails midway.
	// Cleanup uses the current leader (which may differ from port after step-down).
	t.Cleanup(func() {
		leader := h.GetLeaderPort(t)
		h.APIRequest(t, "DELETE", "sys/providers/aws", leader, "")
		h.APIRequest(t, "DELETE", "auth/jwt/role/e2e-aws-sigv4", leader, "")
		h.APIRequest(t, "DELETE", "sys/policies/cbp/e2e-aws-gateway", leader, "")
		h.APIRequest(t, "DELETE", "sys/cred/specs/e2e-aws-sigv4", leader, "")
		h.APIRequest(t, "DELETE", "sys/cred/sources/e2e-aws-local", leader, "")
	})

	// Generate fake AWS credentials at runtime to avoid GitGuardian flags.
	fakeAccessKey := helper.GenerateAWSAccessKeyID()
	fakeSecretKey := helper.GenerateAWSSecretAccessKey()

	// 1. Credential source (local — credentials embedded in spec config)
	status, body := h.APIRequest(t, "POST", "sys/cred/sources/e2e-aws-local", port,
		`{"type":"local"}`)
	if status != 200 && status != 201 && status != 409 {
		t.Fatalf("create credential source: expected 200/201/409, got %d: %s", status, string(body))
	}

	// 2. Credential spec
	specBody := fmt.Sprintf(
		`{"type":"aws_access_keys","source":"e2e-aws-local","config":{"access_key_id":"%s","secret_access_key":"%s"}}`,
		fakeAccessKey, fakeSecretKey)
	status, body = h.APIRequest(t, "POST", "sys/cred/specs/e2e-aws-sigv4", port, specBody)
	if status != 200 && status != 201 && status != 409 {
		t.Fatalf("create credential spec: expected 200/201/409, got %d: %s", status, string(body))
	}

	// 3. Policy granting access to the AWS gateway
	status, body = h.APIRequest(t, "POST", "sys/policies/cbp/e2e-aws-gateway", port,
		`{"policy":"path \"aws/gateway*\" {\n  capabilities = [\"read\",\"create\",\"update\",\"delete\",\"list\"]\n}"}`)
	if status != 200 && status != 201 && status != 204 && status != 409 {
		t.Fatalf("create policy: expected 200/201/204/409, got %d: %s", status, string(body))
	}

	// 4. JWT role that issues aws_access_keys tokens
	status, body = h.APIRequest(t, "POST", "auth/jwt/role/e2e-aws-sigv4", port,
		`{"token_type":"aws","token_policies":["e2e-aws-gateway"],"user_claim":"sub","cred_spec_name":"e2e-aws-sigv4","token_ttl":3600}`)
	if status != 200 && status != 201 && status != 409 {
		t.Fatalf("create JWT role: expected 200/201/409, got %d: %s", status, string(body))
	}

	// 5. AWS provider
	status, body = h.APIRequest(t, "POST", "sys/providers/aws", port, `{"type":"aws"}`)
	if status != 200 && status != 201 && status != 409 {
		t.Fatalf("create AWS provider: expected 200/201/409, got %d: %s", status, string(body))
	}
}

// getWardenAWSCredentials authenticates via JWT and returns the Warden-issued
// AWS access key ID and secret access key.
func getWardenAWSCredentials(t *testing.T, port int) (accessKeyID, secretAccessKey string) {
	t.Helper()

	jwt := h.GetDefaultJWT(t)
	loginBody := fmt.Sprintf(`{"jwt":"%s","role":"e2e-aws-sigv4"}`, jwt)
	status, body := h.DoRequest(t, "POST",
		fmt.Sprintf("%s/v1/auth/jwt/login", h.NodeURL(port)),
		map[string]string{"Content-Type": "application/json"},
		loginBody,
	)
	if status != 200 && status != 201 {
		t.Fatalf("JWT login failed (status %d): %s", status, string(body))
	}

	accessKeyID = h.JSONString(t, body, "data.data.access_key_id")
	secretAccessKey = h.JSONString(t, body, "data.data.secret_access_key")
	if accessKeyID == "" || secretAccessKey == "" {
		t.Fatalf("login response missing AWS credentials: %s", string(body))
	}
	return accessKeyID, secretAccessKey
}

// signSTSRequest creates an HTTP request to the Warden AWS gateway and signs
// it with SigV4 using the given credentials. The request simulates an
// STS GetCallerIdentity call (POST with empty body).
func signSTSRequest(t *testing.T, targetURL, accessKeyID, secretAccessKey string) *http.Request {
	t.Helper()

	body := "Action=GetCallerIdentity&Version=2011-06-15"
	req, err := http.NewRequest(http.MethodPost, targetURL, strings.NewReader(body))
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Compute payload hash
	payloadHash := sha256.Sum256([]byte(body))
	payloadHashHex := hex.EncodeToString(payloadHash[:])

	creds := aws.Credentials{
		AccessKeyID:     accessKeyID,
		SecretAccessKey: secretAccessKey,
	}

	signer := v4.NewSigner()
	err = signer.SignHTTP(context.Background(), creds, req, payloadHashHex, "sts", "us-east-1", time.Now())
	if err != nil {
		t.Fatalf("failed to sign request: %v", err)
	}

	return req
}

// TestSigV4ThroughStandbyForwarding verifies that AWS SigV4 signature
// verification is not broken when requests are forwarded from a standby
// node to the leader via the reverse proxy.
//
// The standby proxy must preserve the original Host header because SigV4
// signs it. If the proxy rewrites Host to the leader's cluster address,
// the signature verification on the leader will fail with 403.
func TestSigV4ThroughStandbyForwarding(t *testing.T) {
	leader := h.GetLeaderPort(t)
	standby := h.GetStandbyPort(t)

	// Provision AWS provider infrastructure
	setupAWSProvider(t, leader)

	// Authenticate and get Warden-issued AWS credentials
	accessKeyID, secretAccessKey := getWardenAWSCredentials(t, leader)

	// --- Test 1: Send SigV4-signed request through STANDBY ---
	standbyURL := fmt.Sprintf("%s/v1/aws/gateway", h.NodeURL(standby))
	req := signSTSRequest(t, standbyURL, accessKeyID, secretAccessKey)

	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request through standby failed: %v", err)
	}
	resp.Body.Close()

	// The key assertion: SigV4 verification must NOT fail.
	// 403 means the Host header was rewritten and broke the signature.
	// Other errors (e.g., 502 from inability to reach real AWS) are
	// acceptable — they mean SigV4 verification passed.
	if resp.StatusCode == http.StatusForbidden {
		t.Fatalf("SigV4 verification failed through standby (status 403): "+
			"Host header was likely rewritten by the proxy, breaking the signature. "+
			"Expected any status other than 403, got %d", resp.StatusCode)
	}
	t.Logf("standby forwarding: status %d (SigV4 verification passed)", resp.StatusCode)

	// --- Test 2: Send SigV4-signed request directly to LEADER (control) ---
	leaderURL := fmt.Sprintf("%s/v1/aws/gateway", h.NodeURL(leader))
	req2 := signSTSRequest(t, leaderURL, accessKeyID, secretAccessKey)

	resp2, err := client.Do(req2)
	if err != nil {
		// Transport-level errors (EOF, connection reset) mean the request
		// passed SigV4 verification and reached the internal proxy stage
		// which failed connecting to the real AWS endpoint. This is fine.
		t.Logf("leader direct: transport error (SigV4 verification passed, proxy-to-AWS failed as expected): %v", err)
		return
	}
	resp2.Body.Close()

	if resp2.StatusCode == http.StatusForbidden {
		t.Fatalf("SigV4 verification failed on leader directly (status 403): "+
			"unexpected — this should always work. Got %d", resp2.StatusCode)
	}
	t.Logf("leader direct: status %d (SigV4 verification passed)", resp2.StatusCode)
}

// signSigV4Request creates an HTTP request with a custom body, signs it with
// SigV4, and returns the request. Useful for testing different payload sizes.
func signSigV4Request(t *testing.T, method, targetURL, body, contentType, accessKeyID, secretAccessKey, service, region string) *http.Request {
	t.Helper()

	req, err := http.NewRequest(method, targetURL, strings.NewReader(body))
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	payloadHash := sha256.Sum256([]byte(body))
	payloadHashHex := hex.EncodeToString(payloadHash[:])

	creds := aws.Credentials{
		AccessKeyID:     accessKeyID,
		SecretAccessKey: secretAccessKey,
	}

	signer := v4.NewSigner()
	err = signer.SignHTTP(context.Background(), creds, req, payloadHashHex, service, region, time.Now())
	if err != nil {
		t.Fatalf("failed to sign request: %v", err)
	}

	return req
}

// sendSigV4AndAssert sends the request and asserts it did NOT get a 403
// (signature verification failure). Returns the status code.
// Transport-level errors are treated as "SigV4 passed" since they mean
// the request got past signature verification to the proxy-to-AWS stage.
func sendSigV4AndAssert(t *testing.T, req *http.Request, label string) int {
	t.Helper()

	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		// Transport errors (EOF, connection reset) mean signature verification
		// passed and the request reached the internal proxy stage.
		t.Logf("%s: transport error (SigV4 passed, proxy-to-AWS failed): %v", label, err)
		return 0
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden {
		t.Fatalf("%s: SigV4 verification failed (status 403) — "+
			"signature was likely broken during forwarding", label)
	}
	t.Logf("%s: status %d (SigV4 verification passed)", label, resp.StatusCode)
	return resp.StatusCode
}

// TestConcurrentSigV4ThroughStandby verifies that concurrent SigV4-signed
// requests forwarded through the standby all pass signature verification.
// This validates there are no race conditions in Host header preservation.
func TestConcurrentSigV4ThroughStandby(t *testing.T) {
	leader := h.GetLeaderPort(t)
	standby := h.GetStandbyPort(t)

	setupAWSProvider(t, leader)
	accessKeyID, secretAccessKey := getWardenAWSCredentials(t, leader)

	const concurrency = 20
	standbyURL := fmt.Sprintf("%s/v1/aws/gateway", h.NodeURL(standby))

	var wg sync.WaitGroup
	var mu sync.Mutex
	var failures []string

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			req := signSTSRequest(t, standbyURL, accessKeyID, secretAccessKey)
			client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
			resp, err := client.Do(req)
			if err != nil {
				// Transport error = SigV4 passed
				return
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()

			if resp.StatusCode == http.StatusForbidden {
				mu.Lock()
				failures = append(failures, fmt.Sprintf("goroutine %d: got 403", idx))
				mu.Unlock()
			}
		}(i)
	}

	wg.Wait()

	if len(failures) > 0 {
		t.Fatalf("SigV4 verification failed on %d/%d concurrent requests through standby:\n%s",
			len(failures), concurrency, strings.Join(failures, "\n"))
	}
	t.Logf("all %d concurrent SigV4 requests through standby passed signature verification", concurrency)
}

// TestSigV4DuringLeaderStepDown verifies that a SigV4-signed request sent
// through a standby during a leader step-down gets a retriable error (503
// or 307) rather than a 403 signature verification failure.
func TestSigV4DuringLeaderStepDown(t *testing.T) {
	leader := h.GetLeaderPort(t)
	standby := h.GetStandbyPort(t)

	setupAWSProvider(t, leader)
	accessKeyID, secretAccessKey := getWardenAWSCredentials(t, leader)

	standbyURL := fmt.Sprintf("%s/v1/aws/gateway", h.NodeURL(standby))

	// Fire SigV4 requests in background while triggering step-down.
	var wg sync.WaitGroup
	var mu sync.Mutex
	var results []int
	var got403 bool

	// Start sending requests concurrently with the step-down.
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Small stagger so requests span the step-down window.
			time.Sleep(time.Duration(i) * 200 * time.Millisecond)

			req := signSTSRequest(t, standbyURL, accessKeyID, secretAccessKey)
			client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
			resp, err := client.Do(req)

			mu.Lock()
			defer mu.Unlock()

			if err != nil {
				// Transport error = SigV4 passed, connection failed (expected during step-down)
				results = append(results, 0)
				return
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			results = append(results, resp.StatusCode)

			if resp.StatusCode == http.StatusForbidden {
				got403 = true
			}
		}()
	}

	// Trigger step-down after a brief delay to overlap with some requests.
	time.Sleep(300 * time.Millisecond)
	h.StepDown(t, leader)

	wg.Wait()

	// Wait for cluster to stabilize for cleanup.
	h.WaitForCluster(t, 15, 2*time.Second)

	if got403 {
		t.Fatalf("SigV4 verification failed (403) during leader step-down — "+
			"Host header was likely corrupted. Results: %v", results)
	}

	t.Logf("step-down results (no 403s): %v", results)
}

// TestLargeSigV4BodyThroughStandby verifies that a large (~500KB)
// SigV4-signed request body is forwarded through the standby without
// corruption. SigV4 signs the payload hash, so any body modification
// during forwarding will cause signature verification to fail.
func TestLargeSigV4BodyThroughStandby(t *testing.T) {
	leader := h.GetLeaderPort(t)
	standby := h.GetStandbyPort(t)

	setupAWSProvider(t, leader)
	accessKeyID, secretAccessKey := getWardenAWSCredentials(t, leader)

	// Build a ~500KB form-encoded body (simulates a large STS request).
	largeValue := strings.Repeat("A", 500*1024)
	body := fmt.Sprintf("Action=GetCallerIdentity&Version=2011-06-15&LargeParam=%s", largeValue)

	standbyURL := fmt.Sprintf("%s/v1/aws/gateway", h.NodeURL(standby))
	req := signSigV4Request(t, http.MethodPost, standbyURL, body,
		"application/x-www-form-urlencoded", accessKeyID, secretAccessKey, "sts", "us-east-1")

	sendSigV4AndAssert(t, req, "large body through standby")

	// Control: same request directly to leader.
	leaderURL := fmt.Sprintf("%s/v1/aws/gateway", h.NodeURL(leader))
	req2 := signSigV4Request(t, http.MethodPost, leaderURL, body,
		"application/x-www-form-urlencoded", accessKeyID, secretAccessKey, "sts", "us-east-1")

	sendSigV4AndAssert(t, req2, "large body direct to leader")
}

// TestSigV4PolicyDenialThroughStandby verifies that a policy denial through
// the standby returns 403 with a "permission denied" message (policy
// enforcement), NOT a 403 from SigV4 signature verification failure.
// This ensures policy errors are distinguishable from signature errors.
func TestSigV4PolicyDenialThroughStandby(t *testing.T) {
	leader := h.GetLeaderPort(t)
	standby := h.GetStandbyPort(t)

	// Generate fake AWS credentials at runtime.
	fakeAccessKey := helper.GenerateAWSAccessKeyID()
	fakeSecretKey := helper.GenerateAWSSecretAccessKey()

	// Register cleanup first so it always runs, even if creation fails midway.
	t.Cleanup(func() {
		cur := h.GetLeaderPort(t)
		h.APIRequest(t, "DELETE", "sys/providers/aws", cur, "")
		h.APIRequest(t, "DELETE", "auth/jwt/role/e2e-aws-deny", cur, "")
		h.APIRequest(t, "DELETE", "sys/policies/cbp/e2e-aws-deny", cur, "")
		h.APIRequest(t, "DELETE", "sys/cred/specs/e2e-aws-deny", cur, "")
		h.APIRequest(t, "DELETE", "sys/cred/sources/e2e-aws-deny", cur, "")
	})

	// Create a separate credential source, spec, and role with a DENY policy.
	status, body := h.APIRequest(t, "POST", "sys/cred/sources/e2e-aws-deny", leader,
		`{"type":"local"}`)
	if status != 200 && status != 201 && status != 409 {
		t.Fatalf("create credential source: expected 200/201/409, got %d: %s", status, string(body))
	}

	specBody := fmt.Sprintf(
		`{"type":"aws_access_keys","source":"e2e-aws-deny","config":{"access_key_id":"%s","secret_access_key":"%s"}}`,
		fakeAccessKey, fakeSecretKey)
	status, body = h.APIRequest(t, "POST", "sys/cred/specs/e2e-aws-deny", leader, specBody)
	if status != 200 && status != 201 && status != 409 {
		t.Fatalf("create credential spec: expected 200/201/409, got %d: %s", status, string(body))
	}

	// Policy that explicitly DENIES the AWS gateway path.
	status, body = h.APIRequest(t, "POST", "sys/policies/cbp/e2e-aws-deny", leader,
		`{"policy":"path \"aws/gateway*\" {\n  capabilities = [\"deny\"]\n}"}`)
	if status != 200 && status != 201 && status != 204 && status != 409 {
		t.Fatalf("create deny policy: expected 200/201/204/409, got %d: %s", status, string(body))
	}

	// JWT role with the deny policy.
	status, body = h.APIRequest(t, "POST", "auth/jwt/role/e2e-aws-deny", leader,
		`{"token_type":"aws","token_policies":["e2e-aws-deny"],"user_claim":"sub","cred_spec_name":"e2e-aws-deny","token_ttl":3600}`)
	if status != 200 && status != 201 && status != 409 {
		t.Fatalf("create JWT role: expected 200/201/409, got %d: %s", status, string(body))
	}

	// AWS provider (may already exist from other tests, ignore conflict).
	h.APIRequest(t, "POST", "sys/providers/aws", leader, `{"type":"aws"}`)

	// Authenticate with the deny-policy role.
	jwt := h.GetDefaultJWT(t)
	loginBody := fmt.Sprintf(`{"jwt":"%s","role":"e2e-aws-deny"}`, jwt)
	status, body = h.DoRequest(t, "POST",
		fmt.Sprintf("%s/v1/auth/jwt/login", h.NodeURL(leader)),
		map[string]string{"Content-Type": "application/json"},
		loginBody,
	)
	if status != 200 && status != 201 {
		t.Fatalf("JWT login failed (status %d): %s", status, string(body))
	}

	accessKeyID := h.JSONString(t, body, "data.data.access_key_id")
	secretAccessKey := h.JSONString(t, body, "data.data.secret_access_key")

	// Send SigV4-signed request through standby — should be denied by policy.
	standbyURL := fmt.Sprintf("%s/v1/aws/gateway", h.NodeURL(standby))
	req := signSTSRequest(t, standbyURL, accessKeyID, secretAccessKey)

	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request through standby failed: %v", err)
	}
	respBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 from policy denial, got %d: %s", resp.StatusCode, string(respBody))
	}

	// The key distinction: the 403 should come from policy enforcement
	// ("permission denied"), NOT from SigV4 verification failure
	// ("Signature does not match" or "Signature verification failed").
	respStr := string(respBody)
	if strings.Contains(respStr, "Signature") || strings.Contains(respStr, "signature") {
		t.Fatalf("got 403 from SigV4 verification instead of policy denial: %s", respStr)
	}

	t.Logf("policy denial through standby: status %d, body=%s (correctly denied by policy, not SigV4)", resp.StatusCode, respStr)
}
