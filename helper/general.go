package helper

import "fmt"

func ToStringMap(src map[string]interface{}) (map[string]string, error) {
	if src == nil {
		return nil, nil
	}
	dst := make(map[string]string, len(src))

	for k, v := range src {
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("key %q contains %T, expected string", k, v)
		}
		dst[k] = s
	}

	return dst, nil
}
