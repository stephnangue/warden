package helper

import (
	"errors"
	"fmt"
	"time"

	"github.com/hashicorp/go-secure-stdlib/parseutil"

	"github.com/stephnangue/warden/framework"
)

// MaxAgeFieldSchema returns the max_age config field every auth method whose
// credentials carry an issue time accepts, so their descriptions stay alike.
// The schema is fresh on each call.
func MaxAgeFieldSchema() *framework.FieldSchema {
	return &framework.FieldSchema{
		Type: framework.TypeDurationSecond,
		Description: "Maximum age of a credential at admission, measured from its issue time (iat): a duration such as 10m, " +
			"or a number of seconds. Credentials older than max_age, or without an issue time, are not admitted. " +
			"Enforced from the role-free admission; role logins do not use it. " +
			"0 or empty leaves it unset.",
	}
}

// ParseMaxAge converts a max_age value, from a config write, storage or a
// mount table config, to a duration: a duration string ("10m"), a number of
// seconds (a number, or a string of digits), or a duration. nil, an empty
// string and zero leave it unset (0); a negative value is refused.
func ParseMaxAge(raw any) (time.Duration, error) {
	d, err := parseutil.ParseDurationSecond(raw)
	if err != nil {
		return 0, fmt.Errorf("max_age: %w", err)
	}
	if d < 0 {
		return 0, fmt.Errorf("max_age: must not be negative, got %s", d)
	}
	return d, nil
}

// ErrNoIssueTime is CheckMaxAge's refusal of a credential that does not say
// when it was issued while a max_age is set.
var ErrNoIssueTime = errors.New("credential has no issue time")

// CheckMaxAge returns why a credential issued at issuedAt (zero when it does
// not say) is too old to admit at now under maxAge, or nil. A maxAge of zero
// or less is unset and admits any credential. Otherwise a credential without
// an issue time is refused, and so is one more than maxAge old; one exactly
// maxAge old is admitted. An issue time after now is not this check's
// concern: it admits.
func CheckMaxAge(maxAge time.Duration, issuedAt, now time.Time) error {
	if maxAge <= 0 {
		return nil
	}
	if issuedAt.IsZero() {
		return ErrNoIssueTime
	}
	if age := now.Sub(issuedAt); age > maxAge {
		return fmt.Errorf("credential is %s old, more than max_age %s", age, maxAge)
	}
	return nil
}
