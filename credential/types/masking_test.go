package types

import (
	"regexp"
	"slices"
	"testing"

	"github.com/stephnangue/warden/credential"
)

// secretLooking matches the config field names that may hold a secret.
var secretLooking = regexp.MustCompile(`secret|password|private_key|api_key|token|credential|passphrase|assertion|_key$`)

// notSecret are field names secretLooking matches that hold no secret: they
// name a secret held elsewhere, describe one, or are a public identifier.
var notSecret = []string{
	"secret_spec", "secret_field", "secret_path", "secret_id", "secret_version", "secret_name", "secret_cache_ttl",
	"token_name", "token_role", "token_expiry",
	"client_assertion_kid",
	"refresh_token_expires_at", "access_token_expires_at",
	"credential_name", "credential_type",
	"access_key", // Scaleway's public access key ID; its secret_key is masked
}

// Every field a spec type declares that may hold a secret is masked on a
// read, so warden-viewer and every other reader of sys/cred/specs sees the
// mask. A new type, or a new field, fails here until it is masked or listed
// in notSecret.
//
// Source drivers declare no config schema, so there is no field list to check
// them against. A source read masks the driver's SensitiveConfigFields and
// every secret its StoredSecrets reports holding (maskSourceConfig), whichever
// list names it.
func TestSpecTypes_SecretLookingFieldsAreMasked(t *testing.T) {
	r := credential.NewTypeRegistry()
	if err := RegisterBuiltinTypes(r); err != nil {
		t.Fatal(err)
	}
	for _, name := range r.ListTypes() {
		ct, err := r.GetByName(name)
		if err != nil {
			t.Fatal(err)
		}
		sensitive := ct.SensitiveConfigFields()
		for _, f := range ct.ConfigSchema() {
			field := f.FieldName()
			if secretLooking.MatchString(field) && !slices.Contains(sensitive, field) && !slices.Contains(notSecret, field) {
				t.Errorf("%s: field %q may hold a secret and is not masked on read (SensitiveConfigFields %v)", name, field, sensitive)
			}
		}
	}
}
