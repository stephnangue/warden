package drivers

import (
	"encoding/json"
	"fmt"
	"strconv"
)

// parseSecretPayload turns raw secret bytes into the credential's fields. It is shared
// by the stores whose secrets are opaque strings — GCP Secret Manager and
// Azure Key Vault — so a payload means the same thing whichever of them holds it.
//
// Such a store holds arbitrary bytes, so unlike a store that holds documents there is
// no single right shape. A JSON object of scalars is vended under its own key names
// — the multi-field secret a chained consumer reads by name, with numbers and booleans
// rendered as strings because that is the only shape this credential type carries.
// Anything that is not a JSON object at all, a plain API key being the common case, is
// vended whole under "value".
//
// A document containing a nested object or array is refused rather than vended either
// way. Blobbing it under "value" would be actively dangerous: a consuming spec that
// names no secret_field takes the sole key when there is only one, so the entire
// document — every secret stored beside the wanted one — would be sent upstream as the
// credential. Dropping the nested field and keeping the rest would be quietly lossy.
// Neither is worth the convenience of accepting a shape nothing here can represent.
func parseSecretPayload(decoded []byte) (map[string]interface{}, error) {
	var fields map[string]interface{}
	if err := json.Unmarshal(decoded, &fields); err != nil || fields == nil {
		// Not a JSON object: the payload is one opaque secret.
		return map[string]interface{}{"value": string(decoded)}, nil
	}
	if len(fields) == 0 {
		return nil, fmt.Errorf("payload is an empty JSON object, carrying no secret")
	}

	out := make(map[string]interface{}, len(fields))
	for k, v := range fields {
		switch typed := v.(type) {
		case string:
			out[k] = typed
		case bool:
			out[k] = strconv.FormatBool(typed)
		case float64:
			// encoding/json decodes every JSON number as a float64. Render integers
			// without a decimal point so a stored port or id reads back as written.
			out[k] = strconv.FormatFloat(typed, 'f', -1, 64)
		case nil:
			return nil, fmt.Errorf("payload field %q is null", k)
		default:
			return nil, fmt.Errorf("payload field %q holds a nested object or array, which a key/value credential cannot carry; store it as its own secret, or as a string", k)
		}
	}
	return out, nil
}
