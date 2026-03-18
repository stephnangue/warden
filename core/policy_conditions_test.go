package core

import (
	"net"
	"testing"
	"time"

	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Parsing and Validation Tests
// =============================================================================

func TestParseConditions_ValidSourceIP_IPv4CIDR(t *testing.T) {
	cond, err := parseAndValidateConditions(map[string][]string{
		"source_ip": {"10.0.0.0/8"},
	})
	require.NoError(t, err)
	require.Len(t, cond.SourceCIDRs, 1)
	assert.Equal(t, "10.0.0.0/8", cond.SourceCIDRs[0].String())
}

func TestParseConditions_ValidSourceIP_MultipleCIDRs(t *testing.T) {
	cond, err := parseAndValidateConditions(map[string][]string{
		"source_ip": {"10.0.0.0/8", "192.168.0.0/16"},
	})
	require.NoError(t, err)
	require.Len(t, cond.SourceCIDRs, 2)
}

func TestParseConditions_ValidSourceIP_IPv6CIDR(t *testing.T) {
	cond, err := parseAndValidateConditions(map[string][]string{
		"source_ip": {"2001:db8::/32"},
	})
	require.NoError(t, err)
	require.Len(t, cond.SourceCIDRs, 1)
	assert.Equal(t, "2001:db8::/32", cond.SourceCIDRs[0].String())
}

func TestParseConditions_ValidSourceIP_BareIPv4(t *testing.T) {
	cond, err := parseAndValidateConditions(map[string][]string{
		"source_ip": {"192.168.1.1"},
	})
	require.NoError(t, err)
	require.Len(t, cond.SourceCIDRs, 1)
	ones, bits := cond.SourceCIDRs[0].Mask.Size()
	assert.Equal(t, 32, ones)
	assert.Equal(t, 32, bits)
}

func TestParseConditions_ValidSourceIP_BareIPv6(t *testing.T) {
	cond, err := parseAndValidateConditions(map[string][]string{
		"source_ip": {"::1"},
	})
	require.NoError(t, err)
	require.Len(t, cond.SourceCIDRs, 1)
	ones, bits := cond.SourceCIDRs[0].Mask.Size()
	assert.Equal(t, 128, ones)
	assert.Equal(t, 128, bits)
}

func TestParseConditions_InvalidSourceIP(t *testing.T) {
	_, err := parseAndValidateConditions(map[string][]string{
		"source_ip": {"not-a-cidr"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid source_ip")
}

func TestParseConditions_EmptySourceIPList(t *testing.T) {
	_, err := parseAndValidateConditions(map[string][]string{
		"source_ip": {},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "requires at least one")
}

func TestParseConditions_ValidTimeWindow(t *testing.T) {
	cond, err := parseAndValidateConditions(map[string][]string{
		"time_window": {"08:00-18:00 UTC"},
	})
	require.NoError(t, err)
	require.Len(t, cond.TimeWindows, 1)
	assert.Equal(t, 8, cond.TimeWindows[0].StartHour)
	assert.Equal(t, 0, cond.TimeWindows[0].StartMinute)
	assert.Equal(t, 18, cond.TimeWindows[0].EndHour)
	assert.Equal(t, 0, cond.TimeWindows[0].EndMinute)
	assert.Equal(t, time.UTC, cond.TimeWindows[0].Location)
}

func TestParseConditions_ValidTimeWindow_MidnightSpan(t *testing.T) {
	cond, err := parseAndValidateConditions(map[string][]string{
		"time_window": {"22:00-06:00 UTC"},
	})
	require.NoError(t, err)
	require.Len(t, cond.TimeWindows, 1)
	assert.Equal(t, 22, cond.TimeWindows[0].StartHour)
	assert.Equal(t, 6, cond.TimeWindows[0].EndHour)
}

func TestParseConditions_ValidTimeWindow_WithMinutes(t *testing.T) {
	cond, err := parseAndValidateConditions(map[string][]string{
		"time_window": {"08:30-17:45 UTC"},
	})
	require.NoError(t, err)
	assert.Equal(t, 8, cond.TimeWindows[0].StartHour)
	assert.Equal(t, 30, cond.TimeWindows[0].StartMinute)
	assert.Equal(t, 17, cond.TimeWindows[0].EndHour)
	assert.Equal(t, 45, cond.TimeWindows[0].EndMinute)
}

func TestParseConditions_InvalidTimeWindow_BadFormat(t *testing.T) {
	_, err := parseAndValidateConditions(map[string][]string{
		"time_window": {"8am-6pm"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid time_window")
}

func TestParseConditions_InvalidTimeWindow_BadTimezone(t *testing.T) {
	_, err := parseAndValidateConditions(map[string][]string{
		"time_window": {"08:00-18:00 Mars/Olympus"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid timezone")
}

func TestParseConditions_InvalidTimeWindow_OutOfRange(t *testing.T) {
	_, err := parseAndValidateConditions(map[string][]string{
		"time_window": {"25:00-18:00 UTC"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "out of range")
}

func TestParseConditions_InvalidTimeWindow_BadMinute(t *testing.T) {
	_, err := parseAndValidateConditions(map[string][]string{
		"time_window": {"08:60-18:00 UTC"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "out of range")
}

func TestParseConditions_EmptyTimeWindowList(t *testing.T) {
	_, err := parseAndValidateConditions(map[string][]string{
		"time_window": {},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "requires at least one")
}

func TestParseConditions_ValidDayOfWeek(t *testing.T) {
	cond, err := parseAndValidateConditions(map[string][]string{
		"day_of_week": {"Mon", "Fri"},
	})
	require.NoError(t, err)
	require.Len(t, cond.DaysOfWeek, 2)
	assert.Equal(t, time.Monday, cond.DaysOfWeek[0])
	assert.Equal(t, time.Friday, cond.DaysOfWeek[1])
}

func TestParseConditions_ValidDayOfWeek_AllDays(t *testing.T) {
	cond, err := parseAndValidateConditions(map[string][]string{
		"day_of_week": {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"},
	})
	require.NoError(t, err)
	require.Len(t, cond.DaysOfWeek, 7)
}

func TestParseConditions_InvalidDayOfWeek_FullName(t *testing.T) {
	_, err := parseAndValidateConditions(map[string][]string{
		"day_of_week": {"Monday"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid day_of_week")
}

func TestParseConditions_InvalidDayOfWeek_Lowercase(t *testing.T) {
	_, err := parseAndValidateConditions(map[string][]string{
		"day_of_week": {"mon"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid day_of_week")
}

func TestParseConditions_EmptyDayOfWeekList(t *testing.T) {
	_, err := parseAndValidateConditions(map[string][]string{
		"day_of_week": {},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "requires at least one")
}

func TestParseConditions_UnknownConditionType(t *testing.T) {
	_, err := parseAndValidateConditions(map[string][]string{
		"hostname": {"foo.example.com"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown condition type")
}

func TestParseConditions_MultipleTypes(t *testing.T) {
	cond, err := parseAndValidateConditions(map[string][]string{
		"source_ip":   {"10.0.0.0/8"},
		"time_window": {"08:00-18:00 UTC"},
		"day_of_week": {"Mon", "Tue", "Wed", "Thu", "Fri"},
	})
	require.NoError(t, err)
	assert.Len(t, cond.SourceCIDRs, 1)
	assert.Len(t, cond.TimeWindows, 1)
	assert.Len(t, cond.DaysOfWeek, 5)
}

// =============================================================================
// Source IP Evaluation Tests
// =============================================================================

func TestEvaluateSourceIP_Match(t *testing.T) {
	cond := &PolicyConditions{
		SourceCIDRs: parseCIDRs(t, "10.0.0.0/8"),
	}
	assert.True(t, cond.Evaluate("10.1.2.3", time.Now()))
}

func TestEvaluateSourceIP_NoMatch(t *testing.T) {
	cond := &PolicyConditions{
		SourceCIDRs: parseCIDRs(t, "10.0.0.0/8"),
	}
	assert.False(t, cond.Evaluate("192.168.1.1", time.Now()))
}

func TestEvaluateSourceIP_MultipleCIDRs_SecondMatches(t *testing.T) {
	cond := &PolicyConditions{
		SourceCIDRs: parseCIDRs(t, "10.0.0.0/8", "192.168.0.0/16"),
	}
	assert.True(t, cond.Evaluate("192.168.1.1", time.Now()))
}

func TestEvaluateSourceIP_EmptyClientIP(t *testing.T) {
	cond := &PolicyConditions{
		SourceCIDRs: parseCIDRs(t, "10.0.0.0/8"),
	}
	assert.False(t, cond.Evaluate("", time.Now()))
}

func TestEvaluateSourceIP_UnparseableClientIP(t *testing.T) {
	cond := &PolicyConditions{
		SourceCIDRs: parseCIDRs(t, "10.0.0.0/8"),
	}
	assert.False(t, cond.Evaluate("not-an-ip", time.Now()))
}

func TestEvaluateSourceIP_IPv6Match(t *testing.T) {
	cond := &PolicyConditions{
		SourceCIDRs: parseCIDRs(t, "2001:db8::/32"),
	}
	assert.True(t, cond.Evaluate("2001:db8::1", time.Now()))
}

func TestEvaluateSourceIP_IPv6NoMatch(t *testing.T) {
	cond := &PolicyConditions{
		SourceCIDRs: parseCIDRs(t, "2001:db8::/32"),
	}
	assert.False(t, cond.Evaluate("2001:db9::1", time.Now()))
}

func TestEvaluateSourceIP_Loopback(t *testing.T) {
	cond := &PolicyConditions{
		SourceCIDRs: parseCIDRs(t, "127.0.0.0/8"),
	}
	assert.True(t, cond.Evaluate("127.0.0.1", time.Now()))
}

// =============================================================================
// Time Window Evaluation Tests
// =============================================================================

func TestEvaluateTimeWindow_WithinRange(t *testing.T) {
	cond := &PolicyConditions{
		TimeWindows: []TimeWindow{{
			StartHour: 8, StartMinute: 0,
			EndHour: 18, EndMinute: 0,
			Location: time.UTC,
		}},
	}
	at := time.Date(2026, 3, 5, 10, 0, 0, 0, time.UTC)
	assert.True(t, cond.Evaluate("", at))
}

func TestEvaluateTimeWindow_OutsideRange(t *testing.T) {
	cond := &PolicyConditions{
		TimeWindows: []TimeWindow{{
			StartHour: 8, StartMinute: 0,
			EndHour: 18, EndMinute: 0,
			Location: time.UTC,
		}},
	}
	at := time.Date(2026, 3, 5, 20, 0, 0, 0, time.UTC)
	assert.False(t, cond.Evaluate("", at))
}

func TestEvaluateTimeWindow_AtStart(t *testing.T) {
	cond := &PolicyConditions{
		TimeWindows: []TimeWindow{{
			StartHour: 8, StartMinute: 0,
			EndHour: 18, EndMinute: 0,
			Location: time.UTC,
		}},
	}
	at := time.Date(2026, 3, 5, 8, 0, 0, 0, time.UTC)
	assert.True(t, cond.Evaluate("", at))
}

func TestEvaluateTimeWindow_AtEnd_Excluded(t *testing.T) {
	cond := &PolicyConditions{
		TimeWindows: []TimeWindow{{
			StartHour: 8, StartMinute: 0,
			EndHour: 18, EndMinute: 0,
			Location: time.UTC,
		}},
	}
	at := time.Date(2026, 3, 5, 18, 0, 0, 0, time.UTC)
	assert.False(t, cond.Evaluate("", at))
}

func TestEvaluateTimeWindow_MidnightSpan_Late(t *testing.T) {
	cond := &PolicyConditions{
		TimeWindows: []TimeWindow{{
			StartHour: 22, StartMinute: 0,
			EndHour: 6, EndMinute: 0,
			Location: time.UTC,
		}},
	}
	at := time.Date(2026, 3, 5, 23, 0, 0, 0, time.UTC)
	assert.True(t, cond.Evaluate("", at))
}

func TestEvaluateTimeWindow_MidnightSpan_Early(t *testing.T) {
	cond := &PolicyConditions{
		TimeWindows: []TimeWindow{{
			StartHour: 22, StartMinute: 0,
			EndHour: 6, EndMinute: 0,
			Location: time.UTC,
		}},
	}
	at := time.Date(2026, 3, 5, 3, 0, 0, 0, time.UTC)
	assert.True(t, cond.Evaluate("", at))
}

func TestEvaluateTimeWindow_MidnightSpan_Outside(t *testing.T) {
	cond := &PolicyConditions{
		TimeWindows: []TimeWindow{{
			StartHour: 22, StartMinute: 0,
			EndHour: 6, EndMinute: 0,
			Location: time.UTC,
		}},
	}
	at := time.Date(2026, 3, 5, 12, 0, 0, 0, time.UTC)
	assert.False(t, cond.Evaluate("", at))
}

func TestEvaluateTimeWindow_TimezoneConversion(t *testing.T) {
	est, err := time.LoadLocation("America/New_York")
	require.NoError(t, err)

	cond := &PolicyConditions{
		TimeWindows: []TimeWindow{{
			StartHour: 8, StartMinute: 0,
			EndHour: 18, EndMinute: 0,
			Location: est,
		}},
	}
	// 15:00 UTC = 10:00 EST → within 08:00-18:00 EST
	at := time.Date(2026, 3, 5, 15, 0, 0, 0, time.UTC)
	assert.True(t, cond.Evaluate("", at))

	// 01:00 UTC = 20:00 EST previous day → outside 08:00-18:00 EST
	at = time.Date(2026, 3, 5, 1, 0, 0, 0, time.UTC)
	assert.False(t, cond.Evaluate("", at))
}

func TestEvaluateTimeWindow_MultipleWindows_SecondMatches(t *testing.T) {
	cond := &PolicyConditions{
		TimeWindows: []TimeWindow{
			{StartHour: 8, EndHour: 12, Location: time.UTC},
			{StartHour: 14, EndHour: 18, Location: time.UTC},
		},
	}
	at := time.Date(2026, 3, 5, 15, 0, 0, 0, time.UTC)
	assert.True(t, cond.Evaluate("", at))
}

// =============================================================================
// Day of Week Evaluation Tests
// =============================================================================

func TestEvaluateDayOfWeek_Match(t *testing.T) {
	cond := &PolicyConditions{
		DaysOfWeek: []time.Weekday{time.Monday, time.Wednesday, time.Friday},
	}
	// 2026-03-02 is a Monday (UTC)
	at := time.Date(2026, 3, 2, 12, 0, 0, 0, time.UTC)
	assert.True(t, cond.Evaluate("", at))
}

func TestEvaluateDayOfWeek_NoMatch(t *testing.T) {
	cond := &PolicyConditions{
		DaysOfWeek: []time.Weekday{time.Monday, time.Tuesday, time.Wednesday, time.Thursday, time.Friday},
	}
	// 2026-03-07 is a Saturday (UTC)
	at := time.Date(2026, 3, 7, 12, 0, 0, 0, time.UTC)
	assert.False(t, cond.Evaluate("", at))
}

func TestEvaluateDayOfWeek_Sunday(t *testing.T) {
	cond := &PolicyConditions{
		DaysOfWeek: []time.Weekday{time.Sunday},
	}
	// 2026-03-08 is a Sunday (UTC)
	at := time.Date(2026, 3, 8, 12, 0, 0, 0, time.UTC)
	assert.True(t, cond.Evaluate("", at))
}

// =============================================================================
// Combined Conditions (AND Semantics) Tests
// =============================================================================

func TestEvaluateConditions_AllTypesMustMatch_AllPass(t *testing.T) {
	cond := &PolicyConditions{
		SourceCIDRs: parseCIDRs(t, "10.0.0.0/8"),
		TimeWindows: []TimeWindow{{
			StartHour: 8, EndHour: 18, Location: time.UTC,
		}},
		DaysOfWeek: []time.Weekday{time.Thursday},
	}
	// 2026-03-05 is a Thursday
	at := time.Date(2026, 3, 5, 10, 0, 0, 0, time.UTC)
	assert.True(t, cond.Evaluate("10.1.2.3", at))
}

func TestEvaluateConditions_IPFails_OthersPass(t *testing.T) {
	cond := &PolicyConditions{
		SourceCIDRs: parseCIDRs(t, "10.0.0.0/8"),
		TimeWindows: []TimeWindow{{
			StartHour: 8, EndHour: 18, Location: time.UTC,
		}},
		DaysOfWeek: []time.Weekday{time.Thursday},
	}
	at := time.Date(2026, 3, 5, 10, 0, 0, 0, time.UTC)
	assert.False(t, cond.Evaluate("192.168.1.1", at))
}

func TestEvaluateConditions_TimeFails_OthersPass(t *testing.T) {
	cond := &PolicyConditions{
		SourceCIDRs: parseCIDRs(t, "10.0.0.0/8"),
		TimeWindows: []TimeWindow{{
			StartHour: 8, EndHour: 18, Location: time.UTC,
		}},
		DaysOfWeek: []time.Weekday{time.Thursday},
	}
	at := time.Date(2026, 3, 5, 20, 0, 0, 0, time.UTC)
	assert.False(t, cond.Evaluate("10.1.2.3", at))
}

func TestEvaluateConditions_DayFails_OthersPass(t *testing.T) {
	cond := &PolicyConditions{
		SourceCIDRs: parseCIDRs(t, "10.0.0.0/8"),
		TimeWindows: []TimeWindow{{
			StartHour: 8, EndHour: 18, Location: time.UTC,
		}},
		DaysOfWeek: []time.Weekday{time.Monday},
	}
	// 2026-03-05 is a Thursday, not Monday
	at := time.Date(2026, 3, 5, 10, 0, 0, 0, time.UTC)
	assert.False(t, cond.Evaluate("10.1.2.3", at))
}

func TestEvaluateConditions_NilConditions(t *testing.T) {
	var cond *PolicyConditions
	assert.True(t, cond.Evaluate("anything", time.Now()))
}

// =============================================================================
// Clone Tests
// =============================================================================

func TestClone_NilConditions(t *testing.T) {
	var cond *PolicyConditions
	assert.Nil(t, cond.Clone())
}

func TestClone_DeepCopy(t *testing.T) {
	cond := &PolicyConditions{
		SourceCIDRs: parseCIDRs(t, "10.0.0.0/8"),
		TimeWindows: []TimeWindow{{
			StartHour: 8, EndHour: 18, Location: time.UTC,
		}},
		DaysOfWeek: []time.Weekday{time.Monday},
	}

	clone := cond.Clone()
	require.NotNil(t, clone)

	// Verify values match
	assert.Equal(t, len(cond.SourceCIDRs), len(clone.SourceCIDRs))
	assert.Equal(t, cond.SourceCIDRs[0].String(), clone.SourceCIDRs[0].String())
	assert.Equal(t, cond.TimeWindows[0].StartHour, clone.TimeWindows[0].StartHour)
	assert.Equal(t, cond.DaysOfWeek[0], clone.DaysOfWeek[0])

	// Verify independence — mutating clone doesn't affect original
	clone.SourceCIDRs[0].IP[0] = 99
	assert.NotEqual(t, cond.SourceCIDRs[0].IP[0], clone.SourceCIDRs[0].IP[0])
}

// =============================================================================
// HCL Policy Parsing Integration Tests
// =============================================================================

func TestParseCBPPolicy_WithConditions(t *testing.T) {
	policy := testParsePolicy(t, `
		path "aws/sts/prod-*" {
			capabilities = ["create"]
			conditions {
				source_ip = ["10.0.0.0/8", "172.16.0.0/12"]
			}
		}
	`)
	require.Len(t, policy.Paths, 1)
	require.NotNil(t, policy.Paths[0].Permissions.ConditionSets)
	require.Len(t, policy.Paths[0].Permissions.ConditionSets, 1)
	assert.Len(t, policy.Paths[0].Permissions.ConditionSets[0].SourceCIDRs, 2)
}

func TestParseCBPPolicy_WithAllConditionTypes(t *testing.T) {
	policy := testParsePolicy(t, `
		path "secret/*" {
			capabilities = ["read"]
			conditions {
				source_ip   = ["10.0.0.0/8"]
				time_window = ["08:00-18:00 UTC"]
				day_of_week = ["Mon", "Tue", "Wed", "Thu", "Fri"]
			}
		}
	`)
	require.Len(t, policy.Paths, 1)
	conds := policy.Paths[0].Permissions.ConditionSets[0]
	assert.Len(t, conds.SourceCIDRs, 1)
	assert.Len(t, conds.TimeWindows, 1)
	assert.Len(t, conds.DaysOfWeek, 5)
}

func TestParseCBPPolicy_WithoutConditions(t *testing.T) {
	policy := testParsePolicy(t, `
		path "secret/*" {
			capabilities = ["read"]
		}
	`)
	require.Len(t, policy.Paths, 1)
	assert.Nil(t, policy.Paths[0].Permissions.ConditionSets)
}

func TestParseCBPPolicy_InvalidCondition(t *testing.T) {
	_, err := ParseCBPPolicy(namespace.RootNamespace, `
		path "secret/*" {
			capabilities = ["read"]
			conditions {
				source_ip = ["not-a-cidr"]
			}
		}
	`)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid source_ip")
}

func TestParseCBPPolicy_UnknownConditionType(t *testing.T) {
	_, err := ParseCBPPolicy(namespace.RootNamespace, `
		path "secret/*" {
			capabilities = ["read"]
			conditions {
				hostname = ["foo.example.com"]
			}
		}
	`)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown condition type")
}

// =============================================================================
// Test Helpers
// =============================================================================

func parseCIDRs(t *testing.T, cidrs ...string) []*net.IPNet {
	t.Helper()
	var result []*net.IPNet
	for _, cidrStr := range cidrs {
		_, ipNet, err := net.ParseCIDR(cidrStr)
		require.NoError(t, err)
		result = append(result, ipNet)
	}
	return result
}
