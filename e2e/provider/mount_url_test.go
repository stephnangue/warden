//go:build e2e

package provider

import (
	"encoding/json"
	"strings"
	"testing"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// TestProviderList_IncludesMountURL verifies the LIST endpoint returns
// a `mount_url` per entry with the namespace + mount path baked in.
// Agents use this to build upstream URLs without doing string surgery
// on $WARDEN_NAMESPACE.
func TestProviderList_IncludesMountURL(t *testing.T) {
	port := h.GetLeaderPort(t)

	status, body := h.APIRequest(t, "GET", "sys/providers?warden-list=true", port, "")
	if status != 200 {
		t.Fatalf("list providers: status %d, body %s", status, string(body))
	}

	var resp struct {
		Data struct {
			Mounts map[string]map[string]interface{} `json:"mounts"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("unmarshal: %v\nbody: %s", err, string(body))
	}
	if len(resp.Data.Mounts) == 0 {
		t.Fatal("expected at least one provider in the list")
	}

	// The e2e setup mounts `vault` in the root namespace. Confirm its
	// mount_url is the canonical /v1/<path>.
	vaultEntry, ok := resp.Data.Mounts["vault/"]
	if !ok {
		t.Fatalf("vault/ not in mounts: %v", resp.Data.Mounts)
	}
	got, _ := vaultEntry["mount_url"].(string)
	if got != "/v1/vault/" {
		t.Errorf("vault mount_url = %q, want /v1/vault/", got)
	}

	// Every entry must carry mount_url, and it must start with /v1/
	// (the api root) and contain the mount key.
	for path, entry := range resp.Data.Mounts {
		mu, _ := entry["mount_url"].(string)
		if mu == "" {
			t.Errorf("%q: mount_url missing", path)
			continue
		}
		if !strings.HasPrefix(mu, "/v1/") {
			t.Errorf("%q: mount_url=%q does not start with /v1/", path, mu)
		}
		if !strings.HasSuffix(mu, "/"+path) {
			t.Errorf("%q: mount_url=%q does not end with mount path", path, mu)
		}
	}
}

// TestProviderRead_IncludesMountURL verifies the READ endpoint returns
// mount_url symmetrically with LIST.
func TestProviderRead_IncludesMountURL(t *testing.T) {
	port := h.GetLeaderPort(t)

	status, body := h.APIRequest(t, "GET", "sys/providers/vault", port, "")
	if status != 200 {
		t.Fatalf("read vault provider: status %d, body %s", status, string(body))
	}

	var resp struct {
		Data map[string]interface{} `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("unmarshal: %v\nbody: %s", err, string(body))
	}
	got, _ := resp.Data["mount_url"].(string)
	if got != "/v1/vault/" {
		t.Errorf("mount_url = %q, want /v1/vault/", got)
	}
}

// TestProviderList_MountURLIncludesNamespace verifies the URL is
// namespace-aware: mounting a provider inside a sub-namespace must
// produce a mount_url that includes that namespace's path.
func TestProviderList_MountURLIncludesNamespace(t *testing.T) {
	port := h.GetLeaderPort(t)
	const ns = "e2e-mount-url-ns"
	const mountName = "vault-in-ns"

	// Pre-clean (cleanup is also wired below in case the test mid-fails).
	h.APIRequest(t, "DELETE", "sys/namespaces/"+ns, port, "")

	createNS, _ := h.APIRequest(t, "POST", "sys/namespaces/"+ns, port, "")
	if createNS != 201 && createNS != 200 {
		t.Fatalf("create namespace: expected 201/200, got %d", createNS)
	}
	t.Cleanup(func() {
		h.APIRequest(t, "DELETE", "sys/namespaces/"+ns, port, "")
	})

	createProv, _ := h.NSAPIRequest(t, "POST", "sys/providers/"+mountName, ns, port, `{"type":"vault"}`)
	if createProv != 200 && createProv != 201 {
		t.Fatalf("mount in sub-namespace: expected 200/201, got %d", createProv)
	}

	status, body := h.NSAPIRequest(t, "GET", "sys/providers?warden-list=true", ns, port, "")
	if status != 200 {
		t.Fatalf("list under sub-namespace: status %d, body %s", status, string(body))
	}

	var resp struct {
		Data struct {
			Mounts map[string]map[string]interface{} `json:"mounts"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	entry, ok := resp.Data.Mounts[mountName+"/"]
	if !ok {
		t.Fatalf("%s/ not found in sub-namespace list: %v", mountName, resp.Data.Mounts)
	}
	got, _ := entry["mount_url"].(string)
	want := "/v1/" + ns + "/" + mountName + "/"
	if got != want {
		t.Errorf("mount_url = %q, want %q", got, want)
	}
}
