package audit

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/stephnangue/warden/logger"
)

// Every path the format tests, the default salt field and the documentation
// use is accepted; so is omitting a field that used to record headers or a
// body, which earlier releases' defaults named.
func TestCheckFieldPath_Accepted(t *testing.T) {
	salt := []string{
		"response.credential.data", "response.credential.data.secret_key",
		"response.credential.metadata", "response.credential.metadata.email",
		"response.credential.credential_id", "response.credential.lease_id", "response.credential.token_id",
		"response.auth_result.principal_id",
		"auth.token_id", "auth.token_accessor", "auth.principal_id", "auth.created_by_ip",
		"auth.policy_results.granting_policies",
		"auth.policy_results.condition.inputs",
		"auth.policy_results.condition.inputs.agent.metadata.env",
		"auth.policy_results.condition.inputs.request.data.model",
		"request.client_ip",
	}
	omit := []string{
		"auth", "request", "response", "error",
		"auth.groups", "auth.discovery", "auth.actors", "auth.user", "auth.principal_id",
		"auth.policy_results", "auth.policy_results.allowed", "auth.policy_results.granting_policies",
		"auth.policy_results.mcp_decision", "auth.policy_results.mcp_client",
		"auth.policy_results.condition", "auth.policy_results.condition.inputs",
		"auth.policy_results.condition.inputs.agent.metadata.env",
		"request.client_ip", "request.path",
		"response.credential", "response.credential.data", "response.credential.data.secret_key",
		"response.credential.metadata.email", "response.auth_result", "response.auth_result.policies",
		"response.status_message", "response.upstream_url", "response.warnings",
		// Retired: no entry records these any more, so omitting them does nothing.
		"request.data", "request.headers", "response.data", "response.headers",
		"request.data.password", "request.headers.Authorization",
	}
	for _, p := range salt {
		if err := checkFieldPath(true, p); err != nil {
			t.Errorf("salt %q refused: %v", p, err)
		}
	}
	for _, p := range omit {
		if err := checkFieldPath(false, p); err != nil {
			t.Errorf("omit %q refused: %v", p, err)
		}
	}
}

// Paths that name no field are refused, each with its reason. Before, every
// one of them was ignored without a word.
func TestCheckFieldPath_Refused(t *testing.T) {
	for _, tc := range []struct {
		salt bool
		path string
		want error
	}{
		{true, "agent.metadata.env", errUnknownFieldPath},
		{true, "auth.policy_results.mcp_decision.condition.inputs", errUnknownFieldPath},
		{true, "auth.policy_results.condition.expression", errUnknownFieldPath},
		{true, "auth.token_id.x", errUnknownFieldPath},
		{true, "auth.token_type", errUnknownFieldPath},
		{true, "error", errUnknownFieldPath},
		{true, "response.credential.data.k.x", errUnknownFieldPath},
		{true, "auth", errNotSaltable},
		{true, "auth.policy_results", errNotSaltable},
		{true, "auth.policy_results.condition", errNotSaltable},
		{true, "response.credential", errNotSaltable},
		{true, "response.auth_result", errNotSaltable},
		{true, "request.data.password", errNeverLogged},
		{true, "request.headers.Authorization", errNeverLogged},
		{true, "response.data", errNeverLogged},
		{false, "agent.metadata.env", errUnknownFieldPath},
		{false, "request.id.x", errUnknownFieldPath},
		{false, "auth.user.subject", errUnknownFieldPath},
		{false, "auth.policy_results.condition.expression", errUnknownFieldPath},
		{false, "response.credential.data.k.x", errUnknownFieldPath},
		{false, "response.credential.metadata.k.x", errUnknownFieldPath},
		{false, "error.x", errUnknownFieldPath},
		{false, "type", errUnknownFieldPath},
		{false, "", errUnknownFieldPath},
		// An unknown name inside each structure.
		{false, "auth.bogus", errUnknownFieldPath},
		{false, "auth.policy_results.bogus", errUnknownFieldPath},
		{false, "request.bogus", errUnknownFieldPath},
		{false, "response.bogus", errUnknownFieldPath},
		{false, "response.credential.bogus", errUnknownFieldPath},
		{false, "response.auth_result.bogus", errUnknownFieldPath},
		{true, "auth.bogus", errUnknownFieldPath},
		{true, "auth.policy_results.bogus", errUnknownFieldPath},
		{true, "request.path", errUnknownFieldPath},
		{true, "response.status_code", errUnknownFieldPath},
		{true, "response.credential.type", errUnknownFieldPath},
		{true, "response.auth_result.token_type", errUnknownFieldPath},
	} {
		if err := checkFieldPath(tc.salt, tc.path); !errors.Is(err, tc.want) {
			t.Errorf("salt=%v %q: got %v, want %v", tc.salt, tc.path, err, tc.want)
		}
	}
}

// omittedWhole are the nested structures omitted only as a whole: a new field
// inside one is covered by omitting it.
var omittedWhole = map[reflect.Type]bool{
	reflect.TypeOf(UserAttribution{}): true,
	reflect.TypeOf(DiscoveryAuth{}):   true,
	reflect.TypeOf(MCPClientInfo{}):   true,
}

// notOmittable are the entry fields no omit path removes: they identify the
// entry rather than describe the request.
var notOmittable = map[string]bool{"type": true, "timestamp": true}

// Every field an audit entry records can be omitted. A field added to an
// entry structure without an omit case fails here, rather than becoming a
// value an operator cannot keep out of their log.
func TestOmit_EveryFieldIsOmittable(t *testing.T) {
	var walk func(prefix string, typ reflect.Type)
	walk = func(prefix string, typ reflect.Type) {
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
			if name == "" || name == "-" {
				continue
			}
			path := prefix + name
			if notOmittable[path] {
				continue
			}
			if err := checkFieldPath(false, path); err != nil {
				t.Errorf("%s (%s.%s) cannot be omitted: %v", path, typ.Name(), field.Name, err)
				continue
			}
			ft := field.Type
			if ft.Kind() == reflect.Pointer {
				ft = ft.Elem()
			}
			if ft.Kind() == reflect.Struct && ft.PkgPath() == typ.PkgPath() && !omittedWhole[ft] {
				walk(path+".", ft)
			}
		}
	}
	walk("", reflect.TypeOf(LogEntry{}))
}

// An unknown path costs nothing at format time: it is skipped, and the paths
// beside it still apply.
func TestJSONFormat_UnknownPathSkippedAtFormatTime(t *testing.T) {
	format := NewJSONFormat(
		WithSaltFunc(func(_ context.Context, s string) (string, error) { return "hmac-sha256:" + s, nil }),
		WithSaltFields([]string{"agent.metadata.env", "auth.token_id"}),
		WithOmitFields([]string{"request.headers", "request.client_ip"}),
	)
	out, err := format.FormatRequest(context.Background(), &LogEntry{
		Timestamp: time.Now(),
		Auth:      &Auth{TokenID: "tok"},
		Request:   &Request{ID: "req-1", ClientIP: "10.0.0.1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if s := string(out); !strings.Contains(s, "hmac-sha256:tok") || strings.Contains(s, "10.0.0.1") || !strings.Contains(s, "req-1") {
		t.Errorf("unexpected output: %s", s)
	}
}

// Enabling refuses a configuration with a path that names no field; creating
// a device from one, as an unseal does from a stored table, drops the path and
// reports it.
func TestFileDeviceFactory_UnknownFieldPaths(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	f := &FileDeviceFactory{}
	f.Initialize(log)
	config := map[string]any{
		"file_path":   filepath.Join(t.TempDir(), "audit.log"),
		"hmac_key":    "k",
		"salt_fields": []any{"auth.token_id", "agent.metadata.env"},
		"omit_fields": []any{"request.headers", "request.id.x"},
	}

	err := f.ValidateConfig(config)
	if err == nil {
		t.Fatal("ValidateConfig accepted paths that name no field")
	}
	for _, want := range []string{`salt_fields "agent.metadata.env"`, `omit_fields "request.id.x"`} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name %s", err, want)
		}
	}

	dev, err := f.Create(context.Background(), "siem/", "", "", config)
	if err != nil {
		t.Fatalf("Create refused a stored configuration: %v", err)
	}
	defer dev.Close()
	warnings := dev.(WarningReporter).Warnings()
	if len(warnings) != 2 || !strings.HasPrefix(warnings[0], "ignored salt_fields") || !strings.HasPrefix(warnings[1], "ignored omit_fields") {
		t.Errorf("warnings = %q", warnings)
	}

	if err := f.ValidateConfig(map[string]any{"file_path": "/tmp/x.log", "salt_fields": []any{"auth.token_id"}}); err != nil {
		t.Errorf("a valid configuration was refused: %v", err)
	}
}
