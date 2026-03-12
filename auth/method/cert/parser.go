package cert

import (
	"encoding/json"
	"fmt"
	"time"
)

func mapToCertAuthConfig(data map[string]any) (*CertAuthConfig, error) {
	dataCopy := make(map[string]any)
	for k, v := range data {
		dataCopy[k] = v
	}

	// Handle token_ttl duration conversion from various source types
	switch ttl := dataCopy["token_ttl"].(type) {
	case string:
		if d, err := time.ParseDuration(ttl); err == nil {
			dataCopy["token_ttl"] = d
		}
	case int:
		dataCopy["token_ttl"] = time.Duration(ttl) * time.Second
	case float64:
		dataCopy["token_ttl"] = time.Duration(int64(ttl)) * time.Second
	case time.Duration:
		// Already a duration, keep as-is
	}

	jsonData, err := json.Marshal(dataCopy)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal map: %w", err)
	}

	var config CertAuthConfig
	if err := json.Unmarshal(jsonData, &config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal to CertAuthConfig: %w", err)
	}

	if config.PrincipalClaim == "" {
		config.PrincipalClaim = "cn"
	}

	if config.TokenTTL == 0 {
		config.TokenTTL = time.Hour
	}

	return &config, nil
}
