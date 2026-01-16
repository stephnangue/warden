package helpers

// MaskValue is the default mask used for sensitive fields
const MaskValue = "***********"

// MaskConfigFields masks sensitive config values based on a list of sensitive field names
func MaskConfigFields(sensitiveFields []string, config map[string]string) map[string]string {
	sensitive := make(map[string]bool)
	for _, f := range sensitiveFields {
		sensitive[f] = true
	}

	masked := make(map[string]string)
	for k, v := range config {
		if sensitive[k] {
			masked[k] = MaskValue
		} else {
			masked[k] = v
		}
	}
	return masked
}

// MaskSingleValue returns the masked value if the field is in the sensitive list
func MaskSingleValue(fieldName, value string, sensitiveFields []string) string {
	for _, f := range sensitiveFields {
		if fieldName == f {
			return MaskValue
		}
	}
	return value
}
