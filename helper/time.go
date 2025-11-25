package helper

import (
	"fmt"
	"time"
)

func FormatTTL(ttlNano int64) string {
	d := time.Duration(ttlNano) * time.Nanosecond
	
	if d.Hours() >= 1 {
		return fmt.Sprintf("%.1fh", d.Hours())
	}
	if d.Minutes() >= 1 {
		return fmt.Sprintf("%.1fm", d.Minutes())
	}
	if d.Seconds() >= 1 {
		return fmt.Sprintf("%.1fs", d.Seconds())
	}
	return fmt.Sprintf("%dns", ttlNano)
}

// For 3,600,000 ns: "3.6 milliseconds"