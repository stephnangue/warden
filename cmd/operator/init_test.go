package operator

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stephnangue/warden/api"
	"github.com/stephnangue/warden/cmd/helpers"
)

// setupInitTest spins up an httptest server that returns the given /v1/sys/init
// response body, installs a real api.Client pointed at it via the helpers test
// hook, captures stdout/stderr, and resets every piece of package-level state
// in cleanup so tests stay independent.
func setupInitTest(t *testing.T, respBody string) (*bytes.Buffer, *bytes.Buffer) {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(respBody))
	}))

	cfg := api.DefaultConfig()
	cfg.Address = server.URL
	client, err := api.NewClient(cfg)
	if err != nil {
		t.Fatalf("api.NewClient: %v", err)
	}
	helpers.SetTestClient(client)

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	helpers.SetOutputWriter(stdout)
	helpers.SetErrorWriter(stderr)

	origShares, origThreshold := secretShares, secretThreshold
	secretShares, secretThreshold = 5, 3

	t.Cleanup(func() {
		server.Close()
		helpers.SetTestClient(nil)
		helpers.SetOutputFormat("")
		helpers.SetFields("")
		helpers.ResetWriters()
		secretShares, secretThreshold = origShares, origThreshold
	})

	return stdout, stderr
}

func TestInit_JSONOutput(t *testing.T) {
	body := `{"data":{"root_token":"hvs.root123","keys":["k1","k2","k3"],"keys_base64":["a2V5MQ==","a2V5Mg==","a2V5Mw=="]}}`
	stdout, stderr := setupInitTest(t, body)
	helpers.SetOutputFormat("json")

	if err := run(nil, nil); err != nil {
		t.Fatalf("run() error: %v", err)
	}

	if stderr.Len() != 0 {
		t.Errorf("expected empty stderr in JSON mode; got %q", stderr.String())
	}

	var got map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\nstdout: %s", err, stdout.String())
	}

	for _, k := range []string{"unseal_keys", "unseal_keys_base64", "recovery_keys", "recovery_keys_base64", "root_token"} {
		if _, ok := got[k]; !ok {
			t.Errorf("JSON output missing field %q", k)
		}
	}

	if got["root_token"] != "hvs.root123" {
		t.Errorf("root_token = %v; want hvs.root123", got["root_token"])
	}

	unseal, ok := got["unseal_keys"].([]any)
	if !ok || len(unseal) != 3 {
		t.Errorf("unseal_keys = %v; want 3-element slice", got["unseal_keys"])
	}

	// Stable schema: recovery_keys must be [] (not null) even when the server
	// omits the field — Shamir-mode bootstraps have no recovery keys.
	recovery, ok := got["recovery_keys"].([]any)
	if !ok {
		t.Errorf("recovery_keys = %v (%T); want empty []any", got["recovery_keys"], got["recovery_keys"])
	} else if len(recovery) != 0 {
		t.Errorf("recovery_keys = %v; want empty slice", recovery)
	}

	if strings.Contains(stdout.String(), "WARDEN INITIALIZATION COMPLETE") {
		t.Errorf("JSON output contains banner text; got %q", stdout.String())
	}
}

// Table-mode banner output is intentionally not asserted here: the existing
// helpers.PrintTable pipeline writes directly to os.Stdout rather than through
// helpers.SetOutputWriter, so the captured buffer never sees it. The banner
// text is unchanged verbatim from pre-change behavior — see the diff on
// cmd/operator/init.go — and the JSON tests below cover the new code path.

func TestInit_AutoUnsealJSON(t *testing.T) {
	body := `{"data":{"root_token":"hvs.x","recovery_keys":["r1","r2"],"recovery_keys_base64":["cjE=","cjI="]}}`
	stdout, _ := setupInitTest(t, body)
	helpers.SetOutputFormat("json")

	if err := run(nil, nil); err != nil {
		t.Fatalf("run() error: %v", err)
	}

	var got map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	unseal, _ := got["unseal_keys"].([]any)
	if len(unseal) != 0 {
		t.Errorf("auto-unseal: unseal_keys = %v; want empty", unseal)
	}
	recovery, ok := got["recovery_keys"].([]any)
	if !ok || len(recovery) != 2 {
		t.Errorf("auto-unseal: recovery_keys = %v; want 2-element slice", got["recovery_keys"])
	}
}

func TestInit_FieldsProjection(t *testing.T) {
	body := `{"data":{"root_token":"hvs.proj","keys":["k1"],"keys_base64":["b1"]}}`
	stdout, _ := setupInitTest(t, body)
	helpers.SetOutputFormat("json")
	helpers.SetFields("root_token")

	if err := run(nil, nil); err != nil {
		t.Fatalf("run() error: %v", err)
	}

	var got map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("--fields root_token: got %d keys; want 1\n%v", len(got), got)
	}
	if got["root_token"] != "hvs.proj" {
		t.Errorf("root_token = %v; want hvs.proj", got["root_token"])
	}
}
