//go:build e2e

package provider

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// An access backend vends credentials in an ordinary response rather than
// proxying traffic, so its access paths are not streaming paths. Agents still
// call them with their own identity, and every auth method is transparent-only,
// so the provider's auto_auth_path is the only way an agent gets in: the JWT it
// presents must be logged in implicitly, exactly as on a gateway path.
//
// The rds provider is driven end to end. Its credential is an IAM auth token, a
// SigV4 presign made locally, so no database is needed; the aws source's one
// network call — the credential probe when it is written — goes to a local STS
// stand-in.

const (
	accessMount   = "e2e-rds-access"
	accessSource  = "e2e-rds-access-aws"
	accessSpec    = "e2e-rds-access-db"
	accessPolicy  = "e2e-rds-access"
	accessRole    = "e2e-rds-access-reader"
	accessGrant   = "app"
	accessDBHost  = "e2e-db.cluster-abc.eu-west-1.rds.amazonaws.com"
	accessPath    = accessMount + "/access/" + accessGrant
	accessDBUser  = "app_ro"
	accessDBName  = "appdb"
	stsCallerBody = `<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <GetCallerIdentityResult>
    <Arn>arn:aws:iam::123456789012:user/e2e-rds</Arn>
    <UserId>AIDAE2ERDSEXAMPLE</UserId>
    <Account>123456789012</Account>
  </GetCallerIdentityResult>
  <ResponseMetadata><RequestId>4c5d6e7f-0000-4000-8000-000000000001</RequestId></ResponseMetadata>
</GetCallerIdentityResponse>`
)

// startCallerIdentityStub answers sts:GetCallerIdentity, the probe an aws
// source with static keys runs before it is first used.
func startCallerIdentityStub(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("Action") != "GetCallerIdentity" {
			http.Error(w, "unexpected STS action", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "text/xml")
		_, _ = w.Write([]byte(stsCallerBody))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// setupAccessEnv mounts the rds provider with auto_auth_path and wires one
// grant to a spec the JWT role's policy may read. Everything is test-local and
// removed consumer-first, which also clears what a killed run left behind.
func setupAccessEnv(t *testing.T, port int) {
	t.Helper()
	stub := startCallerIdentityStub(t)

	mustWrite := func(method, path, body, what string) {
		t.Helper()
		switch status, resp := h.APIRequest(t, method, path, port, body); status {
		case 200, 201, 204:
		default:
			t.Fatalf("%s (status %d): %s", what, status, resp)
		}
	}

	clear := func() {
		h.APIRequest(t, "DELETE", "auth/jwt/role/"+accessRole, port, "")
		h.APIRequest(t, "DELETE", "sys/providers/"+accessMount, port, "")
		h.APIRequest(t, "DELETE", "sys/policies/cbp/"+accessPolicy, port, "")
		h.APIRequest(t, "DELETE", "sys/cred/specs/"+accessSpec, port, "")
		h.APIRequest(t, "DELETE", "sys/cred/sources/"+accessSource, port, "")
	}
	clear()
	t.Cleanup(clear)

	mustWrite("POST", "sys/cred/sources/"+accessSource, `{
		"type":"aws","config":{
			"access_key_id":"AKIAE2ERDSEXAMPLE","secret_access_key":"e2e-not-a-real-secret-key",
			"region":"eu-west-1","sts_endpoint":"`+stub.URL+`"}}`,
		"create the aws source")

	mustWrite("POST", "sys/cred/specs/"+accessSpec, `{
		"type":"db_auth_token","source":"`+accessSource+`","config":{
			"mint_method":"rds_iam_token","db_endpoint":"`+accessDBHost+`",
			"db_user":"`+accessDBUser+`","db_engine":"postgres"}}`,
		"create the rds spec")

	mustWrite("POST", "sys/policies/cbp/"+accessPolicy,
		`{"policy":"path \"`+accessMount+`/access/*\" {\n  capabilities = [\"read\"]\n}"}`,
		"create the access policy")

	mustWrite("POST", "sys/providers/"+accessMount, `{"type":"rds"}`, "mount the rds provider")
	mustWrite("PUT", accessMount+"/config", `{"auto_auth_path":"auth/jwt/"}`, "configure auto_auth_path")
	mustWrite("POST", accessMount+"/grants/"+accessGrant,
		`{"credential_spec":"`+accessSpec+`","db_name":"`+accessDBName+`"}`,
		"create the grant")

	mustWrite("POST", "auth/jwt/role/"+accessRole, `{
		"token_policies":["`+accessPolicy+`"],"cred_spec_name":"`+accessSpec+`",
		"user_claim":"sub","token_ttl":3600}`,
		"create the agent role")
}

func accessRequest(t *testing.T, port int, query string, headers map[string]string) (int, []byte) {
	t.Helper()
	u := fmt.Sprintf("%s/v1/%s%s", h.NodeURL(port), accessPath, query)
	return h.DoRequest(t, "GET", u, headers, "")
}

// assertConnectionString checks the body is a DSN for the grant, with an IAM
// auth token as its password.
func assertConnectionString(t *testing.T, body []byte) {
	t.Helper()
	dsn := h.JSONString(t, body, "data.connection_string")
	for _, want := range []string{
		"host=" + accessDBHost, "user=" + accessDBUser, "dbname=" + accessDBName,
		"X-Amz-Signature=", "Action=connect",
	} {
		if !strings.Contains(dsn, want) {
			t.Fatalf("connection string lacks %q: %s", want, dsn)
		}
	}
}

func TestAccessBackend_ImplicitAuth(t *testing.T) {
	leader := h.GetLeaderPort(t)
	setupAccessEnv(t, leader)
	jwt := h.GetDefaultJWT(t)

	t.Run("JWT with the role as a query parameter", func(t *testing.T) {
		status, body := accessRequest(t, leader, "?role="+accessRole,
			map[string]string{"Authorization": "Bearer " + jwt})
		if status != 200 {
			t.Fatalf("expected 200, got %d: %s", status, body)
		}
		assertConnectionString(t, body)
	})

	t.Run("JWT with the role in X-Warden-Role, through a standby", func(t *testing.T) {
		standby := h.GetStandbyPort(t)
		status, body := accessRequest(t, standby, "", map[string]string{
			"Authorization": "Bearer " + jwt,
			"X-Warden-Role": accessRole,
		})
		if status != 200 {
			t.Fatalf("expected 200, got %d: %s", status, body)
		}
		assertConnectionString(t, body)
	})

	t.Run("a role the JWT cannot assume answers 401", func(t *testing.T) {
		status, body := accessRequest(t, leader, "?role=e2e-no-such-role",
			map[string]string{"Authorization": "Bearer " + jwt})
		if status != 401 {
			t.Fatalf("expected 401, got %d: %s", status, body)
		}
	})

	t.Run("an invalid JWT answers 401", func(t *testing.T) {
		fake := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJmYWtlIn0.invalid-signature"
		status, body := accessRequest(t, leader, "?role="+accessRole,
			map[string]string{"Authorization": "Bearer " + fake})
		if status != 401 {
			t.Fatalf("expected 401, got %d: %s", status, body)
		}
	})

	t.Run("an explicit X-Warden-Token still works", func(t *testing.T) {
		status, body := accessRequest(t, leader, "",
			map[string]string{"X-Warden-Token": h.RootToken(t)})
		if status != 200 {
			t.Fatalf("expected 200, got %d: %s", status, body)
		}
		assertConnectionString(t, body)
	})

	t.Run("the audit records the implicit authentication", func(t *testing.T) {
		node := h.NodeNumberForPort(leader)
		deadline := time.Now().Add(6 * time.Second)
		for {
			for _, e := range h.ReadAuditEntries(t, node, accessPath) {
				if e.Type == "request" && e.Request != nil && e.Request.Transparent &&
					e.Auth != nil && e.Auth.RoleName == accessRole {
					return
				}
			}
			if time.Now().After(deadline) {
				t.Fatalf("no transparent request audit entry for %s under role %s", accessPath, accessRole)
			}
			time.Sleep(200 * time.Millisecond)
		}
	})

	// Last: it changes the mount's config, which the rows above rely on.
	t.Run("without auto_auth_path the JWT is not logged in", func(t *testing.T) {
		if status, body := h.APIRequest(t, "PUT", accessMount+"/config", leader, `{"auto_auth_path":""}`); status != 204 && status != 200 {
			t.Fatalf("clear auto_auth_path (status %d): %s", status, body)
		}
		status, body := accessRequest(t, leader, "?role="+accessRole,
			map[string]string{"Authorization": "Bearer " + jwt})
		if status != 403 {
			t.Fatalf("expected 403, got %d: %s", status, body)
		}
	})
}
