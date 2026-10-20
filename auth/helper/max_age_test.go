package helper

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/framework"
)

func TestCheckMaxAge(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	const maxAge = 10 * time.Minute
	cases := []struct {
		name     string
		maxAge   time.Duration
		issuedAt time.Time
		wantErr  string
	}{
		{"unset admits an old credential", 0, now.Add(-24 * time.Hour), ""},
		{"unset admits one without an issue time", 0, time.Time{}, ""},
		{"negative is unset", -time.Minute, time.Time{}, ""},
		{"no issue time", maxAge, time.Time{}, "credential has no issue time"},
		{"just issued", maxAge, now, ""},
		{"younger", maxAge, now.Add(-maxAge + time.Nanosecond), ""},
		{"exactly max_age", maxAge, now.Add(-maxAge), ""},
		{"a nanosecond over", maxAge, now.Add(-maxAge - time.Nanosecond), "credential is 10m0.000000001s old, more than max_age 10m0s"},
		{"well over", maxAge, now.Add(-time.Hour), "credential is 1h0m0s old, more than max_age 10m0s"},
		{"issued in the future", maxAge, now.Add(time.Minute), ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckMaxAge(tc.maxAge, tc.issuedAt, now)
			if tc.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			assert.EqualError(t, err, tc.wantErr)
		})
	}
	assert.ErrorIs(t, CheckMaxAge(maxAge, time.Time{}, now), ErrNoIssueTime)
}

func TestParseMaxAge(t *testing.T) {
	ok := []struct {
		name string
		raw  any
		want time.Duration
	}{
		{"nil", nil, 0},
		{"empty string", "", 0},
		{"zero", 0, 0},
		{"zero string", "0s", 0},
		{"duration string", "10m", 10 * time.Minute},
		{"stored form", "1h30m0s", 90 * time.Minute},
		{"seconds string", "600", 10 * time.Minute},
		{"seconds int", 600, 10 * time.Minute},
		{"seconds float64", float64(600), 10 * time.Minute},
		{"seconds json.Number", json.Number("600"), 10 * time.Minute},
		{"days", "1d", 24 * time.Hour},
		{"a duration", 5 * time.Minute, 5 * time.Minute},
	}
	for _, tc := range ok {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseMaxAge(tc.raw)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}

	refused := []struct {
		name string
		raw  any
		want string
	}{
		{"negative string", "-5m", "max_age: must not be negative, got -5m0s"},
		{"negative seconds", -60, "max_age: must not be negative, got -1m0s"},
		{"negative duration", -time.Second, "max_age: must not be negative, got -1s"},
		{"not a duration", "soon", "max_age: "},
		{"not a scalar", []string{"10m"}, "max_age: could not parse duration from input"},
		{"a bool", true, "max_age: could not parse duration from input"},
	}
	for _, tc := range refused {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseMaxAge(tc.raw)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
			assert.Zero(t, got)
		})
	}
}

func TestMaxAgeFieldSchema(t *testing.T) {
	s := MaxAgeFieldSchema()
	assert.Equal(t, framework.TypeDurationSecond, s.Type)
	assert.Contains(t, s.Description, "not admitted")
	assert.NotSame(t, s, MaxAgeFieldSchema(), "fresh on each call")
}
