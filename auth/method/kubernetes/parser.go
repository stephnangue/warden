package kubernetes

import (
	"encoding/json"
	"fmt"
	"time"
)

// mapToKubernetesAuthConfig converts an operator-supplied config map
// (from the framework field schema or persisted storage) into a typed
// KubernetesAuthConfig. Duration handling normalizes the various source
// representations (string, int seconds from TypeDurationSecond, float64
// from JSON, native time.Duration) into time.Duration before unmarshal.
func mapToKubernetesAuthConfig(data map[string]any) (*KubernetesAuthConfig, error) {
	dataCopy := make(map[string]any, len(data))
	for k, v := range data {
		dataCopy[k] = v
	}

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
		// Already a duration, keep as-is.
	}

	jsonData, err := json.Marshal(dataCopy)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal config map: %w", err)
	}

	var config KubernetesAuthConfig
	if err := json.Unmarshal(jsonData, &config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal to KubernetesAuthConfig: %w", err)
	}

	if config.TokenTTL == 0 {
		config.TokenTTL = 1 * time.Hour
	}

	return &config, nil
}
