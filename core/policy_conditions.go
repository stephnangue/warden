package core

import (
	"fmt"
	"net"
	"strings"
	"time"
)

// PolicyConditions holds the parsed and validated conditions for a path rule.
// All specified condition types must be satisfied (AND semantics between types).
// Within each type's list, at least one entry must match (OR semantics).
type PolicyConditions struct {
	SourceCIDRs []*net.IPNet   // Parsed CIDR networks from source_ip
	TimeWindows []TimeWindow   // Parsed time window specifications
	DaysOfWeek  []time.Weekday // Parsed day-of-week values
}

// TimeWindow represents a parsed time-of-day window with timezone.
type TimeWindow struct {
	StartHour   int
	StartMinute int
	EndHour     int
	EndMinute   int
	Location    *time.Location
}

// validConditionKeys defines the recognized condition type names.
var validConditionKeys = map[string]bool{
	"source_ip":   true,
	"time_window": true,
	"day_of_week": true,
}

// dayAbbrevToWeekday maps 3-letter abbreviations to time.Weekday.
var dayAbbrevToWeekday = map[string]time.Weekday{
	"Sun": time.Sunday,
	"Mon": time.Monday,
	"Tue": time.Tuesday,
	"Wed": time.Wednesday,
	"Thu": time.Thursday,
	"Fri": time.Friday,
	"Sat": time.Saturday,
}

// parseAndValidateConditions converts the raw HCL conditions map into a
// validated PolicyConditions struct. Returns an error if any condition
// type is unknown or any value is malformed.
func parseAndValidateConditions(raw map[string][]string) (*PolicyConditions, error) {
	for key := range raw {
		if !validConditionKeys[key] {
			return nil, fmt.Errorf("unknown condition type %q", key)
		}
	}

	cond := &PolicyConditions{}

	if cidrs, ok := raw["source_ip"]; ok {
		if len(cidrs) == 0 {
			return nil, fmt.Errorf("source_ip condition requires at least one CIDR")
		}
		for _, cidrStr := range cidrs {
			_, ipNet, err := net.ParseCIDR(cidrStr)
			if err != nil {
				// Try as a bare IP (no prefix length)
				ip := net.ParseIP(cidrStr)
				if ip == nil {
					return nil, fmt.Errorf("invalid source_ip %q: %w", cidrStr, err)
				}
				bits := 32
				if ip.To4() == nil {
					bits = 128
				}
				ipNet = &net.IPNet{
					IP:   ip,
					Mask: net.CIDRMask(bits, bits),
				}
			}
			cond.SourceCIDRs = append(cond.SourceCIDRs, ipNet)
		}
	}

	if windows, ok := raw["time_window"]; ok {
		if len(windows) == 0 {
			return nil, fmt.Errorf("time_window condition requires at least one window")
		}
		for _, winStr := range windows {
			tw, err := parseTimeWindow(winStr)
			if err != nil {
				return nil, fmt.Errorf("invalid time_window %q: %w", winStr, err)
			}
			cond.TimeWindows = append(cond.TimeWindows, tw)
		}
	}

	if days, ok := raw["day_of_week"]; ok {
		if len(days) == 0 {
			return nil, fmt.Errorf("day_of_week condition requires at least one day")
		}
		for _, dayStr := range days {
			day, ok := dayAbbrevToWeekday[dayStr]
			if !ok {
				return nil, fmt.Errorf("invalid day_of_week %q (use Sun, Mon, Tue, Wed, Thu, Fri, Sat)", dayStr)
			}
			cond.DaysOfWeek = append(cond.DaysOfWeek, day)
		}
	}

	return cond, nil
}

// parseTimeWindow parses a time window string like "08:00-18:00 UTC"
// or "22:00-06:00 America/New_York" (midnight-spanning).
func parseTimeWindow(s string) (TimeWindow, error) {
	parts := strings.Fields(s)
	if len(parts) != 2 {
		return TimeWindow{}, fmt.Errorf("expected format 'HH:MM-HH:MM TZ', got %q", s)
	}

	timeRange := parts[0]
	tzStr := parts[1]

	loc, err := time.LoadLocation(tzStr)
	if err != nil {
		return TimeWindow{}, fmt.Errorf("invalid timezone %q: %w", tzStr, err)
	}

	rangeParts := strings.SplitN(timeRange, "-", 2)
	if len(rangeParts) != 2 {
		return TimeWindow{}, fmt.Errorf("expected HH:MM-HH:MM, got %q", timeRange)
	}

	startH, startM, err := parseHHMM(rangeParts[0])
	if err != nil {
		return TimeWindow{}, fmt.Errorf("invalid start time: %w", err)
	}

	endH, endM, err := parseHHMM(rangeParts[1])
	if err != nil {
		return TimeWindow{}, fmt.Errorf("invalid end time: %w", err)
	}

	return TimeWindow{
		StartHour:   startH,
		StartMinute: startM,
		EndHour:     endH,
		EndMinute:   endM,
		Location:    loc,
	}, nil
}

// parseHHMM parses "HH:MM" into hour and minute integers.
func parseHHMM(s string) (int, int, error) {
	var h, m int
	n, err := fmt.Sscanf(s, "%d:%d", &h, &m)
	if err != nil || n != 2 {
		return 0, 0, fmt.Errorf("expected HH:MM, got %q", s)
	}
	if h < 0 || h > 23 || m < 0 || m > 59 {
		return 0, 0, fmt.Errorf("time out of range: %q", s)
	}
	return h, m, nil
}

// Evaluate checks whether the request satisfies all conditions.
// Returns true if all condition types are met, false otherwise.
// A nil PolicyConditions always returns true (unconditional).
func (c *PolicyConditions) Evaluate(clientIP string, now time.Time) bool {
	if c == nil {
		return true
	}

	if len(c.SourceCIDRs) > 0 {
		if !c.evaluateSourceIP(clientIP) {
			return false
		}
	}

	if len(c.TimeWindows) > 0 {
		if !c.evaluateTimeWindows(now) {
			return false
		}
	}

	if len(c.DaysOfWeek) > 0 {
		if !c.evaluateDayOfWeek(now) {
			return false
		}
	}

	return true
}

func (c *PolicyConditions) evaluateSourceIP(clientIP string) bool {
	if clientIP == "" {
		return false
	}

	ip := net.ParseIP(clientIP)
	if ip == nil {
		return false
	}

	for _, cidr := range c.SourceCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

func (c *PolicyConditions) evaluateTimeWindows(now time.Time) bool {
	for i := range c.TimeWindows {
		if c.TimeWindows[i].Contains(now) {
			return true
		}
	}
	return false
}

// Contains checks if a time falls within the window. Handles midnight-spanning
// windows (e.g., 22:00-06:00) by checking if the time is NOT in the
// complement range. End time is exclusive.
func (tw *TimeWindow) Contains(t time.Time) bool {
	locTime := t.In(tw.Location)
	minuteOfDay := locTime.Hour()*60 + locTime.Minute()
	start := tw.StartHour*60 + tw.StartMinute
	end := tw.EndHour*60 + tw.EndMinute

	if start <= end {
		// Normal window: e.g., 08:00-18:00
		return minuteOfDay >= start && minuteOfDay < end
	}
	// Midnight-spanning window: e.g., 22:00-06:00
	return minuteOfDay >= start || minuteOfDay < end
}

func (c *PolicyConditions) evaluateDayOfWeek(now time.Time) bool {
	currentDay := now.UTC().Weekday()
	for _, day := range c.DaysOfWeek {
		if currentDay == day {
			return true
		}
	}
	return false
}

// Clone returns a deep copy of the PolicyConditions.
func (c *PolicyConditions) Clone() *PolicyConditions {
	if c == nil {
		return nil
	}
	clone := &PolicyConditions{}

	if c.SourceCIDRs != nil {
		clone.SourceCIDRs = make([]*net.IPNet, len(c.SourceCIDRs))
		for i, cidr := range c.SourceCIDRs {
			ipCopy := make(net.IP, len(cidr.IP))
			copy(ipCopy, cidr.IP)
			maskCopy := make(net.IPMask, len(cidr.Mask))
			copy(maskCopy, cidr.Mask)
			clone.SourceCIDRs[i] = &net.IPNet{IP: ipCopy, Mask: maskCopy}
		}
	}

	if c.TimeWindows != nil {
		clone.TimeWindows = make([]TimeWindow, len(c.TimeWindows))
		copy(clone.TimeWindows, c.TimeWindows)
	}

	if c.DaysOfWeek != nil {
		clone.DaysOfWeek = make([]time.Weekday, len(c.DaysOfWeek))
		copy(clone.DaysOfWeek, c.DaysOfWeek)
	}

	return clone
}
