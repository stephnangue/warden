package credential

import (
	"fmt"
	"regexp"
)

// uuidPattern matches the canonical 8-4-4-4-12 hex form. Entra tenant ids and
// application (client) ids both take this form.
var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// ValidateUUID reports whether value is a canonical UUID, naming field in the error.
//
// Identifiers checked here end up inside request URLs and form bodies, so the check
// is not cosmetic: a value carrying '/', '?', '#' or a quote would otherwise reshape
// the request it is spliced into.
func ValidateUUID(field, value string) error {
	if !uuidPattern.MatchString(value) {
		return fmt.Errorf("invalid %s '%s': must be a valid UUID", field, value)
	}
	return nil
}
