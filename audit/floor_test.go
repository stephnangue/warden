package audit

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/stephnangue/warden/logical"
)

// An operator's salt_fields adds to the default, never replaces it: listing
// one path, an empty list or null all leave response.credential.data salted.
func TestMapToFileDeviceConfig_SaltFloor(t *testing.T) {
	for _, tc := range []struct {
		name string
		salt any
		want []string
	}{
		{"absent", nil, []string{"response.credential.data"}},
		{"null", "null", []string{"response.credential.data"}},
		{"empty", []any{}, []string{"response.credential.data"}},
		{"one path", []any{"auth.token_id"}, []string{"response.credential.data", "auth.token_id"}},
		{"the floor again", []any{"response.credential.data", "auth.token_id", "auth.token_id"}, []string{"response.credential.data", "auth.token_id"}},
		{"a key under the floor", []any{"response.credential.data.secret_key"}, []string{"response.credential.data"}},
		{"a key, then its parent", []any{"auth.policy_results.condition.inputs.agent.metadata.env", "auth.policy_results.condition.inputs"}, []string{"response.credential.data", "auth.policy_results.condition.inputs"}},
		{"empty strings dropped", []any{"", "auth.principal_id"}, []string{"response.credential.data", "auth.principal_id"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := map[string]any{}
			switch tc.salt {
			case nil:
			case "null":
				data["salt_fields"] = nil
			default:
				data["salt_fields"] = tc.salt
			}
			conf, err := mapToFileDeviceConfig(data)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(conf.SaltFields, tc.want) {
				t.Errorf("salt fields = %q, want %q", conf.SaltFields, tc.want)
			}
		})
	}
}

// The floor is never appended to in place: two devices created from the same
// defaults keep their own lists.
func TestMapToFileDeviceConfig_FloorNotShared(t *testing.T) {
	a, err := mapToFileDeviceConfig(map[string]any{"salt_fields": []any{"auth.token_id"}})
	if err != nil {
		t.Fatal(err)
	}
	b, err := mapToFileDeviceConfig(map[string]any{"salt_fields": []any{"auth.principal_id"}})
	if err != nil {
		t.Fatal(err)
	}
	if a.SaltFields[1] != "auth.token_id" || b.SaltFields[1] != "auth.principal_id" {
		t.Fatalf("devices share a salt list: %q, %q", a.SaltFields, b.SaltFields)
	}
	if !reflect.DeepEqual(defaultSaltFields, []string{"response.credential.data"}) {
		t.Fatalf("the floor was written: %q", defaultSaltFields)
	}
}

// Omit paths are kept as given, each once; nothing is omitted by default.
func TestMapToFileDeviceConfig_OmitFields(t *testing.T) {
	conf, err := mapToFileDeviceConfig(map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	if len(conf.OmitFields) != 0 {
		t.Errorf("default omit fields = %q, want none", conf.OmitFields)
	}
	conf, err = mapToFileDeviceConfig(map[string]any{"omit_fields": []any{"auth.groups", "auth.groups", "request.client_ip"}})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"auth.groups", "request.client_ip"}; !reflect.DeepEqual(conf.OmitFields, want) {
		t.Errorf("omit fields = %q, want %q", conf.OmitFields, want)
	}
}

// secretEntry carries a distinct sentinel in every field a salt path names.
func secretEntry() *LogEntry {
	return &LogEntry{
		Timestamp: time.Now(),
		Auth: &Auth{
			TokenID:       "S-TOKEN-ID",
			TokenAccessor: "S-ACCESSOR",
			PrincipalID:   "S-PRINCIPAL",
			CreatedByIP:   "S-CREATED-IP",
			PolicyResults: &PolicyResults{
				Allowed:          true,
				GrantingPolicies: []string{"S-POLICY"},
				Condition:        &logical.ConditionResult{Decision: "allow", Inputs: map[string]string{"agent.metadata.env": "S-INPUT"}},
			},
		},
		Request: &Request{ID: "req-1", ClientIP: "S-CLIENT-IP"},
		Response: &Response{
			StatusCode: 200,
			Credential: &Credential{
				CredentialID: "S-CRED-ID",
				LeaseID:      "S-LEASE",
				TokenID:      "S-CRED-TOKEN",
				Data:         map[string]string{"secret_key": "S-CRED-DATA"},
				Metadata:     map[string]string{"email": "S-CRED-META"},
			},
			AuthResult: &AuthResult{PrincipalID: "S-AUTH-RESULT"},
		},
	}
}

// everySaltPath is every salt path the format accepts, one per field of
// secretEntry.
var everySaltPath = []string{
	"auth.token_id", "auth.token_accessor", "auth.principal_id", "auth.created_by_ip",
	"auth.policy_results.granting_policies", "auth.policy_results.condition.inputs",
	"request.client_ip",
	"response.credential.credential_id", "response.credential.lease_id", "response.credential.token_id",
	"response.credential.metadata",
	"response.auth_result.principal_id",
}

// formatBoth formats entry as a request and as a response with format.
func formatBoth(t *testing.T, format *JSONFormat, entry *LogEntry) string {
	t.Helper()
	req, err := format.FormatRequest(context.Background(), entry)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := format.FormatResponse(context.Background(), entry)
	if err != nil {
		t.Fatal(err)
	}
	return string(req) + string(resp)
}

// A custom salt_fields still salts the credential data a device would have
// salted by default; before the floor, it was written in clear.
func TestJSONFormatFor_CustomSaltKeepsFloor(t *testing.T) {
	conf, err := mapToFileDeviceConfig(map[string]any{"hmac_key": "k", "salt_fields": []any{"auth.token_id"}})
	if err != nil {
		t.Fatal(err)
	}
	format, warnings := jsonFormatFor(conf)
	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %q", warnings)
	}
	out := formatBoth(t, format, secretEntry())
	for _, secret := range []string{"S-CRED-DATA", "S-TOKEN-ID"} {
		if strings.Contains(out, secret) {
			t.Errorf("%s written in clear: %s", secret, out)
		}
	}
	if !strings.Contains(out, "hmac-sha256:") {
		t.Error("nothing was salted")
	}
}

// Without an HMAC key a device cannot salt: every salt path, the floor
// included, is omitted instead, and the change is reported. Each salt path
// has an omit counterpart, or its value would be written in clear here.
func TestJSONFormatFor_NoKeyOmitsSaltFields(t *testing.T) {
	salt := make([]any, 0, len(everySaltPath))
	for _, p := range everySaltPath {
		salt = append(salt, p)
	}
	conf, err := mapToFileDeviceConfig(map[string]any{"salt_fields": salt})
	if err != nil {
		t.Fatal(err)
	}
	format, warnings := jsonFormatFor(conf)
	if len(warnings) != 1 || !strings.Contains(warnings[0], "no hmac_key") {
		t.Fatalf("warnings = %q, want the no-key fallback", warnings)
	}
	out := formatBoth(t, format, secretEntry())
	if strings.Contains(out, "S-") {
		t.Errorf("a value meant to be salted was written: %s", out)
	}
	if !strings.Contains(out, `"req-1"`) {
		t.Errorf("fields not listed were dropped too: %s", out)
	}
}

// The single-key salt path for condition inputs is omitted as a key.
func TestJSONFormatFor_NoKeyOmitsOneConditionInput(t *testing.T) {
	conf, err := mapToFileDeviceConfig(map[string]any{"salt_fields": []any{"auth.policy_results.condition.inputs.agent.metadata.env"}})
	if err != nil {
		t.Fatal(err)
	}
	format, _ := jsonFormatFor(conf)
	entry := secretEntry()
	entry.Auth.PolicyResults.Condition.Inputs["request.path"] = "visible"
	out := formatBoth(t, format, entry)
	if strings.Contains(out, "S-INPUT") || !strings.Contains(out, "visible") {
		t.Errorf("want only agent.metadata.env omitted: %s", out)
	}
}
