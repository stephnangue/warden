package spiffe

import (
	"encoding/json"
	"fmt"
	"time"
)

// mapToSPIFFEAuthConfig converts a config map (from request field data or stored
// JSON) into a SPIFFEAuthConfig, normalizing token_ttl from the several source
// types it can arrive as.
func mapToSPIFFEAuthConfig(data map[string]any) (*SPIFFEAuthConfig, error) {
	dataCopy := make(map[string]any, len(data))
	for k, v := range data {
		dataCopy[k] = v
	}

	// token_ttl may be: string (manual/storage), int (TypeDurationSecond via
	// d.GetOk), float64 (JSON decode), or time.Duration (config copy).
	switch ttl := dataCopy["token_ttl"].(type) {
	case string:
		if d, err := time.ParseDuration(ttl); err == nil {
			dataCopy["token_ttl"] = d
		} else {
			// A corrupted stored value must not fail the whole config (and the
			// mount's Initialize); fall back to the default.
			dataCopy["token_ttl"] = time.Hour
		}
	case int:
		dataCopy["token_ttl"] = time.Duration(ttl) * time.Second
	case float64:
		dataCopy["token_ttl"] = time.Duration(int64(ttl)) * time.Second
	case time.Duration:
		// already a duration
	}

	jsonData, err := json.Marshal(dataCopy)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal map: %w", err)
	}
	var config SPIFFEAuthConfig
	if err := json.Unmarshal(jsonData, &config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal to SPIFFEAuthConfig: %w", err)
	}
	if config.TokenTTL == 0 {
		config.TokenTTL = time.Hour
	}
	return &config, nil
}
